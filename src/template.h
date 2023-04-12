#ifndef QUAI_TEMPLATE_H
#define QUAI_TEMPLATE_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <atomic>

#include "messages.h"
// #include "blake3.cu"
#include "uv.h"
#include "constants.h"

typedef struct mining_template_t {
    job_t *job;
    std::atomic<uint32_t> ref_count;

    uint64_t chain_task_count; // increase this by one everytime the template for the chain is updated
} mining_template_t;

void store_template__ref_count(mining_template_t *template_ptr, uint32_t value)
{
    atomic_store(&(template_ptr->ref_count), value);
}

uint32_t add_template__ref_count(mining_template_t *template_ptr, uint32_t value)
{
    return atomic_fetch_add(&(template_ptr->ref_count), value);
}

uint32_t sub_template__ref_count(mining_template_t *template_ptr, uint32_t value)
{
    return atomic_fetch_sub(&(template_ptr->ref_count), value);
}

void free_template(mining_template_t *template_ptr)
{
    uint32_t old_count = sub_template__ref_count(template_ptr, 1);
    // uint32_t old_count = 1;
    if (old_count == 1) { // fetch_sub returns original value
        free_job(template_ptr->job);
        free(template_ptr);
    }
}

std::atomic<mining_template_t*> mining_template = {};
std::atomic<uint64_t> mining_count = { 0 };
uint64_t task_count = { 0 };
bool mining_templates_initialized = false;

mining_template_t* load_template()
{
    return atomic_load(&(mining_template));
}

void store_template(mining_template_t* new_template)
{
    atomic_store(&(mining_template), new_template);
}

void update_templates(job_t *job)
{
    mining_template_t *new_template = (mining_template_t *)malloc(sizeof(mining_template_t));
    new_template->job = job;
    store_template__ref_count(new_template, 1); // referred by mining_templates

    task_count += 1;
    new_template->chain_task_count = task_count;

    // TODO: optimize with atomic_exchange
    mining_template_t *last_template = load_template();
    if (last_template) {
        free_template(last_template);
    }
    store_template(new_template);
}

bool expire_template_for_new_block(mining_template_t *template_ptr)
{
    mining_template_t *latest_template = load_template();
    if (latest_template) {
        store_template(NULL);
        free_template(latest_template);
        return true;
    } else {
        return false;
    }

    mining_templates_initialized = false;
}

bool ready_to_mine() {
    if (load_template()) {
        return true;
    } else {
        return false;
    }
}

#endif // QUAI_TEMPLATE_H
