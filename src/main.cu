#include <assert.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <chrono>
#include <mutex>

#include "constants.h"
#include "uv.h"
#include "messages.h"
#include "blake3.cu"
#include "worker.h"
#include "template.h"
#include "mining.h"
#include "getopt.h"
#include "log.h"
#include<unistd.h>

std::atomic<uint32_t> found_solutions{0};

typedef std::chrono::high_resolution_clock Time;
typedef std::chrono::duration<double> duration_t;
typedef std::chrono::time_point<std::chrono::high_resolution_clock> time_point_t;

uv_loop_t *loop;
uv_stream_t *tcp;

time_point_t start_time = Time::now();

std::atomic<int> gpu_count;
std::atomic<int> worker_count;
std::atomic<uint64_t> total_mining_count;
std::atomic<uint64_t> device_mining_count[max_gpu_num];
bool use_device[max_gpu_num];

int port = 8008;
char broker_ip[16];
uv_timer_t reconnect_timer;
uv_tcp_t *uv_socket;
uv_connect_t *uv_connect;

void setup_gpu_worker_count(int _gpu_count, int _worker_count)
{
    gpu_count.store(_gpu_count);
    worker_count.store(_worker_count);
}

void on_write_end(uv_write_t *req, int status)
{
    if (status < 0)
    {
        LOGERR("error on_write_end %d\n", status);
    }
    free(req);
}

std::mutex write_mutex;
uint8_t write_buffer[4096 * 1024];
void submit_new_block(mining_worker_t *worker)
{
    expire_template_for_new_block(load_worker__template(worker));

    const std::lock_guard<std::mutex> lock(write_mutex);

    uint8_t temp_write_buffer[4096 * 1024];


    char method_str[] = "{\"method\":\"quai_rawHeader\",\"params\":[\"";      // Create the JSON-RPC to proxy including the necessary hashes
    ssize_t buf_size = write_new_block(worker, temp_write_buffer);

    char* ascii_string = (char*)malloc(buf_size*2 + 1);
    for (int i = 0; i < NONCE_LEN; i++) {
        sprintf(&ascii_string[i*2], "%02x", temp_write_buffer[i]);
    }
    ascii_string[buf_size*2] = '\0';

    char method_str2[] = "\"],\"id\":1,\"jsonrpc\":\"2.0\"}\n";

    memcpy(write_buffer, method_str, strlen(method_str));
    memcpy(write_buffer + strlen(method_str), ascii_string, strlen(ascii_string));
    memcpy(write_buffer + strlen(method_str) + strlen(ascii_string), method_str2, strlen(method_str2));

    uv_buf_t buf = uv_buf_init((char *)write_buffer, strlen(method_str) + strlen(ascii_string) + strlen(method_str2));
    print_hex("new solution: nonce", (uint8_t *) hasher_buf(worker, true), NONCE_LEN);
    print_hex("new solution: hash", (uint8_t *) hasher_hash(worker, true), 32);

    uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
    uint32_t buf_count = 1;

    uv_write(write_req, tcp, &buf, buf_count, on_write_end);
    free(ascii_string);
    LOG("Sent solution to proxy\n");
    found_solutions.fetch_add(1, std::memory_order_relaxed);
}

void mine_with_timer(uv_timer_t *timer);

static void register_proxy(uv_stream_t* tcp)
{
    char method_str[] = "{\"method\":\"quai_submitLogin\",\"params\":[\"0x0000000000000000000000000000000000000001\",\"password\"],\"id\":1,\"jsonrpc\":\"2.0\"}\n";

    uv_buf_t buf = uv_buf_init(method_str, strlen(method_str));

    uv_write_t* write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
    write_req->data = method_str;

    uv_write(write_req, tcp, &buf, 1, on_write_end);
    
    LOG("Proxy registered\n");
}

void mine(mining_worker_t *worker)
{
    time_point_t start = Time::now();

    if (!ready_to_mine())
    {
        worker->timer.data = worker;
        uv_timer_start(&worker->timer, mine_with_timer, 500, 0);
    } else {
        mining_count.fetch_add(mining_steps);
        setup_template(worker, load_template(0));
        start_worker_mining(worker);

        // duration_t elapsed = Time::now() - start;
        // LOG("=== mining time: %fs\n", elapsed.count());
    }
}

void mine_with_req(uv_work_t *req)
{
    mining_worker_t *worker = load_req_worker(req);
    mine(worker);
}

void mine_with_async(uv_async_t *handle)
{
    mining_worker_t *worker = (mining_worker_t *)handle->data;
    mine(worker);
}

void mine_with_timer(uv_timer_t *timer)
{
    mining_worker_t *worker = (mining_worker_t *)timer->data;
    mine(worker);
}

void after_mine(uv_work_t *req, int status)
{
    return;
}

void worker_stream_callback(cudaStream_t stream, cudaError_t status, void *data)
{
    mining_worker_t *worker = (mining_worker_t *)data;
    if (hasher_found_good_hash(worker, true))
    {
        store_worker_found_good_hash(worker, true);
        submit_new_block(worker);
    }

    mining_template_t *template_ptr = load_worker__template(worker);
    uint32_t chain_index = 0;
    mining_count.fetch_sub(mining_steps);
    mining_count.fetch_add(hasher_hash_count(worker, true));
    total_mining_count.fetch_add(hasher_hash_count(worker, true));
    device_mining_count[worker->device_id].fetch_add(hasher_hash_count(worker, true));
    free_template(template_ptr);
    worker->async.data = worker;
    uv_async_send(&(worker->async));
}

void start_mining()
{
    assert(mining_templates_initialized == true);

    start_time = Time::now();

    for (uint32_t i = 0; i < worker_count.load(); i++)
    {
        if (use_device[mining_workers[i].device_id])
        {
            uv_queue_work(loop, &req[i], mine_with_req, after_mine);
        }
    }
}

void start_mining_if_needed()
{
    if (!mining_templates_initialized)
    {
        if (load_template(0) != NULL)
        {
            LOG("All templates initialized\n")
            mining_templates_initialized = true;
            start_mining();
        }
    }
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void log_hashrate(uv_timer_t *timer)
{
    time_point_t current_time = Time::now();
    if (current_time > start_time)
    {
        duration_t eplased = current_time - start_time;
        LOG("hashrate: %.0f MH/s ", total_mining_count.load() / eplased.count() / 1000000);
        for (int i = 0; i < gpu_count; i++)
        {
            LOG_WITHOUT_TS("gpu%d: %.0f MH/s ", i, device_mining_count[i].load() / eplased.count() / 1000000);
        }
        LOG_WITHOUT_TS("solutions: %u\n", found_solutions.load(std::memory_order_relaxed));
    }
}

uint8_t read_buf[2048 * 1024];
blob_t read_blob = {read_buf, 0};

server_message_t *decode_buf(const uv_buf_t *buf, ssize_t nread) {
    blob_t read_blob = * (blob_t*)malloc(sizeof(blob_t));
    read_blob.blob = (uint8_t*)malloc(nread * sizeof(uint8_t));
    read_blob.len = nread;

    memcpy(read_blob.blob, buf->base, nread);

    return decode_server_message(&read_blob);
}

void connect_to_broker();

void try_to_reconnect(uv_timer_t *timer){
    read_blob.len = 0;
    free(uv_socket);
    free(uv_connect);
    connect_to_broker();
    uv_timer_stop(timer);
}

void on_read(uv_stream_t *server, ssize_t nread, const uv_buf_t *buf)
{
    // LOG("Received %d bytes from server\n", nread);
    if (nread < 0)
    {
        LOGERR("error on_read %ld: might be that the full node is not synced, or miner wallets are not setup, try to reconnect\n", nread);
        uv_timer_start(&reconnect_timer, try_to_reconnect, 5000, 0);
        return;
    }

    if (nread == 0)
    {
        LOG("No data received\n");
        return;
    }

    LOG("Received new header from server\n");
    server_message_t* server_msg = decode_buf(buf, nread);

    if (server_msg) {
        switch (server_msg->kind)
        {
            case JOBS:
                update_templates(server_msg->job);
                start_mining_if_needed();
                break;
        }
        free_server_message_except_jobs(server_msg);
    }

    free(buf->base);
}

void on_connect(uv_connect_t *req, int status)
{
    if (status < 0)
    {
        LOGERR("connection error %d: might be that the full node is not reachable, try to reconnect\n", status);
        uv_timer_start(&reconnect_timer, try_to_reconnect, 1000, 0);
        return;
    }

    tcp = req->handle;
    register_proxy((uv_stream_t*)tcp);
    int result = uv_read_start(req->handle, alloc_buffer, on_read);
}

void connect_to_broker(){
    uv_socket = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
    uv_tcp_nodelay(uv_socket, 1);
    
    struct sockaddr_in dest;
    uv_ip4_addr(broker_ip, port, &dest);
    
    uv_tcp_init(loop, uv_socket);

    uv_tcp_bind(uv_socket, (struct sockaddr *)&dest, 0);

    uv_connect = (uv_connect_t *)malloc(sizeof(uv_connect_t));

    uv_tcp_connect(uv_connect, uv_socket, (const struct sockaddr *)&dest, on_connect);

}

bool is_valid_ip_address(char *ip_address)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));
    return result != 0;
}

int hostname_to_ip(char *ip_address, char *hostname)
{
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int res = getaddrinfo(hostname, NULL, &hints, &servinfo);
    if (res != 0)
    {
        LOGERR("getaddrinfo: %s\n", gai_strerror(res));
        return 1;
    }

    struct sockaddr_in *h = (struct sockaddr_in *)servinfo->ai_addr;
    strcpy(ip_address, inet_ntoa(h->sin_addr));

    freeaddrinfo(servinfo);
    return 0;
}
#ifndef MINER_VERSION
#define MINER_VERSION "unknown"
#endif

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);

    #ifdef _WIN32
    WSADATA wsa;
    // current winsocket version is 2.2
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0)
    {
        LOGERR("Initialize winsock failed: %d\n", rc);
        exit(1);
    }
    #endif

    LOG("Running gpu-miner version : %s\n", MINER_VERSION);

    int gpu_count = 0;
    cudaGetDeviceCount(&gpu_count);
    LOG("GPU count: %d\n", gpu_count);
    for (int i = 0; i < gpu_count; i++)
    {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);
        LOG("GPU #%d - %s has #%d cores\n", i, prop.name, get_device_cores(i));
        use_device[i] = true;
    }

    int command;
    while ((command = getopt(argc, argv, "p:g:a:")) != -1)
    {
        switch (command)
        {
        case 'p':
            port = atoi(optarg);
            break;
        case 'a':
            if (is_valid_ip_address(optarg))
            {
                strcpy(broker_ip, optarg);
            }
            else
            {
                hostname_to_ip(broker_ip, optarg);
            }
            break;

        case 'g':
            for (int i = 0; i < gpu_count; i++)
            {
                use_device[i] = false;
            }
            optind--;
            for (; optind < argc && *argv[optind] != '-'; optind++)
            {
                int device = atoi(argv[optind]);
                if (device < 0 || device >= gpu_count) {
                    LOGERR("Invalid gpu index %d\n", device);
                    exit(1);
                }
                use_device[device] = true;
            }
            break;
        default:
            LOGERR("Invalid command %c\n", command);
            exit(1);
        }
    }
    LOG("will connect to broker @%s:%d\n", broker_ip, port);

    #ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    #endif

    mining_workers_init(gpu_count);
    LOG("worker count: %d\n", gpu_count);
    setup_gpu_worker_count(gpu_count, gpu_count * parallel_mining_works_per_gpu);

    loop = uv_default_loop();
    uv_timer_init(loop, &reconnect_timer);
    connect_to_broker();

    for (int i = 0; i < worker_count; i++)
    {
        uv_async_init(loop, &(mining_workers[i].async), mine_with_async);
        uv_timer_init(loop, &(mining_workers[i].timer));
    }

    uv_timer_t log_timer;
    uv_timer_init(loop, &log_timer);
    uv_timer_start(&log_timer, log_hashrate, 5000, 20000);

    uv_run(loop, UV_RUN_DEFAULT);

    uv_loop_close(loop);
    free(loop);

    return 0;
}
