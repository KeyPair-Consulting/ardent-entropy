/* ************************************************************************************************
 * Copyright (C) 2026 Symbiotic Systems Research, LLC
 * All Rights Reserved * Proprietary and confidential
 * 
 * The methods and techniques described herein are considered 
 * trade secrets and/or confidential. Reproduction or distribution, 
 * in whole or in part, is forbidden except by express written 
 * permission of Symbiotic Systems Research, LLC.
 * Please contact <info@symsysresearch.com> for licensing information.
 * 
 * NO WARRANTY, EXPLICIT OR IMPLICIT, IS PROVIDED.
 * In no event shall the author be liable for any claim or damages.
 * 
 * Author: Randall Steck
 * ***********************************************************************************************
 * Simple producer/consumer stress test for ringbuffer.c
 *
 * Usage:
 *
 *      ring_stress <ring_size_bytes> <iterations>
 *
 * ***********************************************************************************************/

 #define _POSIX_C_SOURCE 200809L

 #include <errno.h>
 #include <inttypes.h>
 #include <pthread.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 
 #include <openssl/rand.h>
 
 #include "kpep/kpep.h"
 #include "../source/seeding/ringbuffer.h"
 
 #define BLOCK_SIZE          32
 #define PREFILL_BLOCKS      8
 #define PROGRESS_INTERVAL   1000000UL
 
 typedef struct {
 
     RING_CTX *ring;
 
     pthread_mutex_t lock;
 
     uint8_t *reference;
 
     size_t iterations;
 
     size_t ring_size;
 
     volatile int producer_done;
 
     size_t producer_start;

     uint64_t enqueue_retries;
     uint64_t dequeue_retries;
 
 } STRESS_CTX;
 
 typedef struct {
 
     STRESS_CTX *ctx;
 
 } THREAD_ARGS;
 
 
 /******************************************************************************
  * Time
  ******************************************************************************/
 
 static double current_time(void)
 {
     struct timespec ts;
 
     clock_gettime(CLOCK_MONOTONIC, &ts);
 
     return (double)ts.tv_sec +
            ((double)ts.tv_nsec / 1000000000.0);
 }
 
 
 /******************************************************************************
  * Hex dump
  ******************************************************************************/
 
 static void dump_block(const char *title,
                        const uint8_t *buf)
 {
     size_t i;
 
     printf("%s\n", title);
 
     for (i = 0; i < BLOCK_SIZE; i++) {
 
         printf("%02x", buf[i]);
 
         if ((i & 15) == 15)
             printf("\n");
         else
             printf(" ");
     }
 }
 
 
 /******************************************************************************
  * Random block
  ******************************************************************************/
 
 static void random_block(uint8_t block[BLOCK_SIZE])
 {
     if (!RAND_bytes_ex(NULL,
                        block,
                        BLOCK_SIZE,
                        0)) {
 
         fprintf(stderr,
                 "RAND_bytes_ex() failed\n");
 
         exit(EXIT_FAILURE);
     }
 }
 
 
 /******************************************************************************
  * Usage
  ******************************************************************************/
 
 static void usage(const char *prog)
 {
     fprintf(stderr,
         "Usage:\n\n"
         "    %s <ring_size_bytes> <iterations>\n\n"
         "Example:\n\n"
         "    %s 4096 10000000\n\n",
         prog,
         prog);
 
     exit(EXIT_FAILURE);
 }
 
 
 /******************************************************************************
  * Parse positive integer
  ******************************************************************************/
 
 static size_t parse_size(const char *s)
 {
     char *end = NULL;
 
     errno = 0;
 
     uint64_t value = strtoull(s,
                               &end,
                               10);
 
     if (errno ||
         end == s ||
         *end != '\0')
         usage("ring_stress");
 
     return (size_t)value;
 }

 /******************************************************************************
 * Producer Thread
 ******************************************************************************/

static void *producer_thread(void *arg)
{
    THREAD_ARGS *args = arg;
    STRESS_CTX *ctx = args->ctx;

    uint8_t block[BLOCK_SIZE];

    size_t i;

    for (i = ctx->producer_start;
        i < ctx->iterations;
        i++) {

        random_block(block);

        for (;;) {

            pthread_mutex_lock(&ctx->lock);

            memcpy(ctx->reference + (i * BLOCK_SIZE),
                    block,
                    BLOCK_SIZE);

            KPEP_RESULT rv =
                ring_enqueue(ctx->ring,
                             block,
                             BLOCK_SIZE);

            pthread_mutex_unlock(&ctx->lock);

            if (rv == KPEP_R_SUCCESS)
                break;

            ctx->enqueue_retries++;

            sched_yield();
        }

        if ((i != 0) &&
            ((i % PROGRESS_INTERVAL) == 0)) {

            printf("Producer: %zu / %zu\n",
                   i,
                   ctx->iterations);

            fflush(stdout);
        }
    }

    return NULL;
}


/******************************************************************************
 * Consumer Thread
 ******************************************************************************/

static void *consumer_thread(void *arg)
{
    THREAD_ARGS *args = arg;
    STRESS_CTX *ctx = args->ctx;

    uint8_t block[BLOCK_SIZE];

    size_t i;

    for (i = 0; i < ctx->iterations; i++) {

        for (;;) {

            pthread_mutex_lock(&ctx->lock);

            KPEP_RESULT rv =
                ring_dequeue(ctx->ring,
                             block,
                             BLOCK_SIZE);

            pthread_mutex_unlock(&ctx->lock);

            if (rv == KPEP_R_SUCCESS)
                break;

            ctx->dequeue_retries++;

            sched_yield();
        }

        if (memcmp(block,
                   ctx->reference + (i * BLOCK_SIZE),
                   BLOCK_SIZE) != 0) {

            printf("\n");
            printf("**************************************************\n");
            printf("Verification FAILED\n");
            printf("Iteration : %zu\n", i);
            printf("**************************************************\n\n");

            dump_block("Expected:",
                       ctx->reference + (i * BLOCK_SIZE));

            printf("\n");

            dump_block("Received:",
                       block);

            printf("\n");

            exit(EXIT_FAILURE);
        }

        if ((i != 0) &&
            ((i % PROGRESS_INTERVAL) == 0)) {

            printf("Consumer: %zu / %zu\n",
                   i,
                   ctx->iterations);

            fflush(stdout);
        }
    }

    return NULL;
}

/******************************************************************************
 * Main
 ******************************************************************************/

 int main(int argc, char *argv[])
 {
     STRESS_CTX ctx;
 
     THREAD_ARGS args;
 
     pthread_t producer;
     pthread_t consumer;
 
     size_t prefill;
     size_t i;
 
     double start;
     double finish;
     double elapsed;
 
     uint8_t block[BLOCK_SIZE];
 
     memset(&ctx, 0, sizeof(ctx));
 
     if (argc != 3)
         usage(argv[0]);
 
     ctx.ring_size  = parse_size(argv[1]);
     ctx.iterations = parse_size(argv[2]);
 
     if (ctx.ring_size < BLOCK_SIZE) {
         fprintf(stderr,
                 "Ring size must be at least %u bytes\n",
                 BLOCK_SIZE);
         return EXIT_FAILURE;
     }
 
     if (ring_new(&ctx.ring, ctx.ring_size) != KPEP_R_SUCCESS) {
         fprintf(stderr,
                 "ring_new() failed\n");
         return EXIT_FAILURE;
     }
 
     pthread_mutex_init(&ctx.lock, NULL);
 
     ctx.reference = malloc(ctx.iterations * BLOCK_SIZE);
 
     if (!ctx.reference) {
         fprintf(stderr,
                 "malloc() failed\n");
         return EXIT_FAILURE;
     }
 
     args.ctx = &ctx;
 
     /*
      * Prefill the ring.
      */
 
     prefill = ctx.ring_size / BLOCK_SIZE;
 
     if (prefill > PREFILL_BLOCKS)
         prefill = PREFILL_BLOCKS;
 
     if (prefill > ctx.iterations)
         prefill = ctx.iterations;
 
     printf("Prefilling ring with %zu blocks...\n", prefill);
 
     for (i = 0; i < prefill; i++) {
 
         random_block(block);
 
         memcpy(ctx.reference + (i * BLOCK_SIZE),
                block,
                BLOCK_SIZE);
 
         if (ring_enqueue(ctx.ring,
                          block,
                          BLOCK_SIZE) != KPEP_R_SUCCESS) {
 
             fprintf(stderr,
                     "Prefill enqueue failed\n");
 
             return EXIT_FAILURE;
         }
     }
     ctx.producer_start = prefill;
 
     start = current_time();
 
     pthread_create(&consumer,
                    NULL,
                    consumer_thread,
                    &args);
 
     pthread_create(&producer,
                    NULL,
                    producer_thread,
                    &args);
 
     pthread_join(producer, NULL);
     pthread_join(consumer, NULL);
 
     finish = current_time();
 
     elapsed = finish - start;
 
     printf("\n");
     printf("=========================================\n");
     printf("Stress test completed successfully\n");
     printf("=========================================\n");
     printf("Iterations          : %zu\n", ctx.iterations);
     printf("Ring Size           : %zu bytes\n", ctx.ring_size);
     printf("Elapsed             : %.3f sec\n", elapsed);
     printf("Blocks/sec          : %.0f\n",
            ctx.iterations / elapsed);
     printf("Throughput          : %.2f MB/sec\n",
            ((double)ctx.iterations * BLOCK_SIZE) /
            (1024.0 * 1024.0 * elapsed));
     printf("Enqueue retries     : %" PRIu64 "\n",
            ctx.enqueue_retries);
     printf("Dequeue retries     : %" PRIu64 "\n",
            ctx.dequeue_retries);
 
     ring_free(ctx.ring);
 
     free(ctx.reference);
 
     pthread_mutex_destroy(&ctx.lock);
 
     return EXIT_SUCCESS;
 }