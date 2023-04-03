#ifndef ALEPHIUM_WORKER_H
#define ALEPHIUM_WORKER_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <atomic>
#include <random>

#include "messages.h"
#include "blake3.cu"
#include "uv.h"
#include "template.h"
#include "log.h"

typedef struct mining_worker_t {
    uint32_t id;

    int device_id;
    cudaStream_t stream;
    int grid_size;
    int block_size;
    union hasher {
        inline_blake::blake3_hasher *inline_hasher;
        ref_blake::blake3_hasher *ref_hasher;
    };

    hasher host_hasher;
    hasher device_hasher;

    bool is_inline_miner;

    std::atomic<bool> found_good_hash;
    std::atomic<mining_template_t *> template_ptr;

    std::mt19937 random_gen;

    uv_async_t async;
    uv_timer_t timer;
} mining_worker_t;


#define NONCE_LEN 24
#define MINER_IMPL(worker) ((worker)->is_inline_miner ? inline_blake::blake3_hasher_mine:ref_blake::blake3_hasher_mine)
#define HASHER(worker, host) ((host) ? (worker)->host_hasher:(worker)->device_hasher)
#define HASHER_ELEM(hasher, is_inline, elem) ((is_inline) ? (hasher).inline_hasher->elem:(hasher).ref_hasher->elem)


// Helper methods
void *hasher(mining_worker_t *self, bool is_host) {
    return self->is_inline_miner ? reinterpret_cast<void *>(HASHER(self, is_host).inline_hasher)
                                 : reinterpret_cast<void *>(HASHER(self, is_host).ref_hasher);
}

void **hasher_ptr(mining_worker_t *self, bool is_host) {
    return self->is_inline_miner ? reinterpret_cast<void **>(&HASHER(self, is_host).inline_hasher)
                                 : reinterpret_cast<void **>(&HASHER(self, is_host).ref_hasher);
}

size_t hasher_len(mining_worker_t *self) {
    return self->is_inline_miner ? sizeof(inline_blake::blake3_hasher)
                                 : sizeof(ref_blake::blake3_hasher);
}

uint8_t *hasher_buf(mining_worker_t *self, bool is_host) {
    return self->is_inline_miner ? HASHER(self, is_host).inline_hasher->buf
                                 : HASHER(self, is_host).ref_hasher->buf;
}

uint8_t *hasher_hash(mining_worker_t *self, bool is_host) {
    return self->is_inline_miner ? HASHER(self, is_host).inline_hasher->hash
                                 : HASHER(self, is_host).ref_hasher->hash;
}

size_t hasher_hash_len(mining_worker_t *self) {
    return self->is_inline_miner ? sizeof(self->host_hasher.inline_hasher->hash)
                                 : sizeof(self->host_hasher.ref_hasher->hash);
}

uint32_t hasher_hash_count(mining_worker_t *self, bool is_host) {
    return self->is_inline_miner ? HASHER(self, is_host).inline_hasher->hash_count
                                 : HASHER(self, is_host).ref_hasher->hash_count;
}

int hasher_found_good_hash(mining_worker_t *self, bool is_host) {
    return self->is_inline_miner ? HASHER(self, is_host).inline_hasher->found_good_hash
                                 : HASHER(self, is_host).ref_hasher->found_good_hash;
}


void mining_worker_init(mining_worker_t *self, uint32_t id, int device_id) {
    self->id = id;

    self->device_id = device_id;
    cudaSetDevice(device_id);
    TRY(cudaStreamCreate(&(self->stream)));
    config_cuda(device_id, &self->grid_size, &self->block_size, &self->is_inline_miner);
    LOG("Worker %d: device id %d, grid size %d, block size %d. Using %s kernel\n", self->id, self->device_id,
           self->grid_size, self->block_size, self->is_inline_miner ? "inline" : "reference");

    TRY(cudaMallocHost(hasher_ptr(self, true), hasher_len(self)));
    TRY(cudaMalloc(hasher_ptr(self, false), hasher_len(self)));
    memset(hasher_buf(self, true), 0, BLAKE3_BUF_CAP);
    memset(hasher_hash(self, true), 0, hasher_hash_len(self));
    self->random_gen.seed(self->id + (uint64_t) self + (uint64_t) hasher(self, true) + rand());

}

bool load_worker__found_good_hash(mining_worker_t *worker) {
    return atomic_load(&(worker->found_good_hash));
}

void store_worker_found_good_hash(mining_worker_t *worker, bool value) {
    atomic_store(&(worker->found_good_hash), value);
}

mining_template_t *load_worker__template(mining_worker_t *worker) {
    return atomic_load(&(worker->template_ptr));
}

void store_worker__template(mining_worker_t *worker, mining_template_t *template_ptr) {
    atomic_store(&(worker->template_ptr), template_ptr);
}

void reset_worker(mining_worker_t *worker) {
    std::uniform_int_distribution<> distrib(0, UINT8_MAX);
    mining_template_t *template_ptr = worker->template_ptr.load();
    job_t *job = template_ptr->job;

    for (int i = 0; i < NONCE_LEN; i++) {                  // Initializes the first nonce to random data
        // hasher_buf(worker, true)[i] = distrib(worker->random_gen);
        hasher_buf(worker, true)[i] = 0;
    }

    memcpy(hasher_buf(worker, true) + NONCE_LEN, job->header_blob.blob, job->header_blob.len);
    assert((NONCE_LEN + job->header_blob.len) == -1);
    assert(1 == 0);
    assert((NONCE_LEN + job->header_blob.len + 63) / 64 * 64 == BLAKE3_BUF_CAP);

    // size_t target_zero_len = 32 - job->target.len;
    size_t target_zero_len = 0;

    memcpy(HASHER_ELEM(worker->host_hasher, worker->is_inline_miner, target), job->target.blob,
           job->target.len);

    printf("Resetting worker\n");
    // memcpy(HASHER_ELEM(worker->host_hasher, worker->is_inline_miner, target) + target_zero_len, job->target.blob,
    //        sizeof(job->target));
    // HASHER_ELEM(worker->host_hasher, worker->is_inline_miner, from_group) = job->from_group;
    // HASHER_ELEM(worker->host_hasher, worker->is_inline_miner, to_group) = job->to_group;
    HASHER_ELEM(worker->host_hasher, worker->is_inline_miner, hash_count) = 0;
    HASHER_ELEM(worker->host_hasher, worker->is_inline_miner, found_good_hash) = false;

    print_hex("sealhash: ", (uint8_t *) hasher_buf(worker, true) + NONCE_LEN, 32);

    store_worker_found_good_hash(worker, false);
}

typedef struct mining_req {
    std::atomic<mining_worker_t *> worker;
} mining_req_t;

uv_work_t req[max_worker_num] = {NULL};
mining_worker_t mining_workers[max_worker_num];

mining_worker_t *load_req_worker(uv_work_t *req) {
    mining_req_t *mining_req = (mining_req_t *) req->data;
    return atomic_load(&(mining_req->worker));
}

void store_req_data(ssize_t worker_id, mining_worker_t *worker) {
    if (!req[worker_id].data) {
        req[worker_id].data = malloc(sizeof(mining_req_t));
    }
    mining_req_t *mining_req = (mining_req_t *) (req[worker_id].data);
    atomic_store(&(mining_req->worker), worker);
}

void mining_workers_init(int gpu_count) {
    for (size_t i = 0; i < gpu_count * parallel_mining_works_per_gpu; i++) {
        mining_worker_t *worker = mining_workers + i;
        mining_worker_init(worker, (uint32_t) i, i % gpu_count);
        store_req_data(i, worker);
    }
}

ssize_t write_new_block(mining_worker_t *worker, uint8_t *write_buf) {
    job_t *job = load_worker__template(worker)->job;
    uint8_t *nonce = worker->is_inline_miner ? worker->host_hasher.inline_hasher->buf
                                             : worker->host_hasher.ref_hasher->buf;
    uint8_t *write_pos = write_buf;

    // ssize_t block_size = 24 + job->header_blob.len + job->txs_blob.len;
    ssize_t block_size = job->target.len + job->header_blob.len;
    ssize_t message_size = job->target.len + 1;

    // write_size(&write_pos, message_size);
    // write_byte(&write_pos, 0); // message type
    // write_size(&write_pos, block_size);
    write_bytes(&write_pos, nonce, NONCE_LEN);
    // write_blob(&write_pos, &job->header_blob);
    // write_bytes(&write_pos, '\n', 1);
    // memset(write_pos, '\0', 1);
    // write_blob(&write_pos, &job->txs_blob);

    return message_size;
}

void setup_template(mining_worker_t *worker, mining_template_t *template_ptr) {
    add_template__ref_count(template_ptr, 1);
    store_worker__template(worker, template_ptr);
}

#endif // ALEPHIUM_WORKER_H
