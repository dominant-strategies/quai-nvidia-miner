#ifndef ALEPHIUM_MESSAGE_H
#define ALEPHIUM_MESSAGE_H

#define __STDC_FORMAT_MACROS


#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"

#define NONCE_LEN 8
#define HEADER_LEN 32

typedef struct blob_t {
    uint8_t *blob;
    ssize_t len;
} blob_t;

void free_blob(blob_t *blob)
{
    free(blob->blob);
}

char *bytes_to_hex(uint8_t *bytes, ssize_t len)
{
    ssize_t hex_len = 2 * len + 1;
    char *hex_string = (char *)malloc(hex_len);
    memset(hex_string, 0, hex_len);

    uint8_t *byte_cursor = bytes;
    char *hex_cursor = hex_string;
    ssize_t count = 0;
    while (count < len) {
        sprintf(hex_cursor, "%02x", *byte_cursor);
        byte_cursor++;
        count++;
        hex_cursor += 2;
    }

    return hex_string;
}

void print_hex(const char* prefix, uint8_t *data, ssize_t nread)
{
    char *hex_string = bytes_to_hex(data, nread);
    LOG("%s: %s\n", prefix, hex_string);
    free(hex_string);
}

char hex_to_byte(char hex)
{
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    } else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    } else {
        exit(1);
    }
}

void hex_to_bytes(const char *hex_data, blob_t *buf)
{
    size_t hex_len = strlen(hex_data);
    assert(hex_len % 2 == 0);

    buf->len = hex_len / 2;
    buf->blob = (uint8_t *)malloc(buf->len);
    memset(buf->blob, 0, buf->len);

    for (size_t pos = 0; pos < hex_len; pos += 2) {
        char left = hex_to_byte(hex_data[pos]);
        char right = hex_to_byte(hex_data[pos + 1]);
        buf->blob[pos / 2] = (left << 4) + right;
    }
}

typedef struct header_msg_t {
    char* header_msg;
} header_msg_t;

// job struct
typedef struct job_t {
    blob_t header_blob;
    // blob_t txs_blob;
    blob_t target;
} job_t;

void free_job(job_t *job) {
    free_blob(&job->header_blob);
    // free_blob(&job->txs_blob);
    free_blob(&job->target);
    free(job);
}

typedef struct submit_result_t {
    int from_group;
    int to_group;
    bool status;
} submit_result_t;

typedef enum server_message_kind {
    JOBS,
    SUBMIT_RESULT,
} server_message_kind;

typedef struct server_message_t {
    server_message_kind kind;
    union {
        job_t *job;
        submit_result_t *submit_result;
    };
} server_message_t;

void free_server_message(server_message_t *message)
{
    switch (message->kind)
    {
    case JOBS:
        free(message->job);
        break;

    case SUBMIT_RESULT:
        free(message->submit_result);
        break;
    }

    free(message);
}

void free_server_message_except_jobs(server_message_t *message)
{
    switch (message->kind)
    {
    case JOBS:
        break;

    case SUBMIT_RESULT:
        free(message->submit_result);
        break;
    }

    free(message);
}

void write_size(uint8_t **bytes, ssize_t size)
{
    (*bytes)[0] = (size >> 24) & 0xFF;
    (*bytes)[1] = (size >> 16) & 0xFF;
    (*bytes)[2] = (size >> 8) & 0xFF;
    (*bytes)[3] = size & 0xFF;
    *bytes = *bytes + 4;
    return;
}

ssize_t decode_size(uint8_t *bytes)
{
    return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
}

ssize_t extract_size(uint8_t **bytes)
{
    ssize_t size = decode_size(*bytes);
    *bytes = *bytes + 4;
    return size;
}

void write_byte(uint8_t **bytes, uint8_t byte)
{
    (*bytes)[0] = byte;
    *bytes = *bytes + 1;
}

uint8_t extract_byte(uint8_t **bytes)
{
    uint8_t byte = **bytes;
    *bytes = *bytes + 1;
    return byte;
}

bool extract_bool(uint8_t **bytes)
{
    uint8_t byte = extract_byte(bytes);
    switch (byte)
    {
    case 0:
        return false;
    case 1:
        return true;
    default:
        LOGERR("Invaid bool value\n");
        exit(1);
    }
}

void write_bytes(uint8_t **bytes, uint8_t *data, ssize_t len)
{
    memcpy(*bytes, data, len);
    *bytes = *bytes + len;
}

void write_blob(uint8_t **bytes, blob_t *blob)
{
    write_bytes(bytes, blob->blob, blob->len);
}

void extract_blob(uint8_t **bytes, blob_t *blob)
{
    ssize_t size = extract_size(bytes);
    blob->len = size;
    blob->blob = (uint8_t *)malloc(size * sizeof(uint8_t));
    LOG("blob: %ld\n", blob->len);
    memcpy(blob->blob, *bytes, size);
    *bytes = *bytes + size;

}

void extract_submit_result(uint8_t **bytes, submit_result_t *result)
{
    result->from_group = extract_size(bytes);
    result->to_group = extract_size(bytes);
    result->status = extract_bool(bytes);
}

// important: processing message
server_message_t *decode_server_message(blob_t *blob)
{
    uint8_t *target = blob->blob;
    uint8_t *header = blob->blob + NONCE_LEN;
    ssize_t len = blob->len;
    // for (int i = 0; i < len; i++) {
    //     LOG("Byte value: 0x%u\n", bytes[i]);
    // }

    job_t* new_job = (job_t*) malloc(sizeof(job_t));

    new_job->target.len = NONCE_LEN;
    new_job->target.blob = (uint8_t*) malloc(new_job->target.len * sizeof(uint8_t));
    memcpy(new_job->target.blob, target, new_job->target.len);

    new_job->header_blob.len = HEADER_LEN;
    new_job->header_blob.blob = (uint8_t*) malloc(new_job->header_blob.len * sizeof(uint8_t));
    memcpy(new_job->header_blob.blob, header, new_job->header_blob.len);

    // printf("%02x\n", new_job->target);
    // printf("%llu\n", new_job->header_blob.blob[31]);

    server_message_t *server_message = (server_message_t *)malloc(sizeof(server_message_t));
        server_message->kind = JOBS;
        server_message->job = new_job;
    
    return server_message;
}

#endif // ALEPHIUM_MESSAGE_H
