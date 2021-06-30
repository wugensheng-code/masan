/*
 * Copyright (c) 2006-2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2021-06-02     RTT       the first version
 */

#include <stdlib.h>
#include <stdint.h>
#include <rtthread.h>

int global_array[5] = {-1};

/* Use after free (dangling pointer dereference) */
static void use_after_free(void)
{
    rt_uint16_t arr[] = {1,2,3};
    rt_uint16_t *p = arr;

    p = rt_malloc(5);
    rt_free(p);
    arr[0] = *p;
    *p = 0;  /* BOOM: access to released memory */
}

/* Heap buffer overflow */
static void heap_buffer_overflow(void)
{
    int i, *p;
    uint8_t c;

    p = rt_malloc(10);
    c = *((uint8_t*)p);
    for(int j=0; j<10; j++) {
      p[j] = j; /* BOOM: accessing beyond allocated memory */
    }
    rt_free(p);
    i = *p; /* BOOM: access to released memory! */
}

/* Stack buffer overflow */
static void stack_buffer_overflow(void)
{
    char a[3] = {'#'};
    a[6] = '*';
    a[2] = a[6];
}

static void global_buffer_overflow(void)
{
    global_array[5] = global_array[8];  /* BOOM */
}


static void masan_sample(int argc, char**argv)
{
    if (argc < 2)
    {
        rt_kprintf("Please input: 'masan_sample<use_after_free|heap_buffer_overflow|stack_buffer_overflow|global_buffer_overflow>'\n");
        return;
    }

    if (!rt_strcmp(argv[1], "use_after_free"))
    {
        rt_kprintf(
                "\0\0static void use_after_free(void)\n"
                "\0\0{\n"
                "\0\0\0\0rt_uint16_t arr[] = {1,2,3};\n"
                "\0\0\0\0rt_uint16_t *p = arr;\n"
                "\0\0\0\0p = rt_malloc(5);\n"
                "\0\0\0\0rt_free(p);\n"
                "\0\0\0\0arr[0] = *p;\n"
                "\0\0\0\0*p = 0;  /* BOOM: access to released memory */\n"
                "\0\0}\n"
                );
        use_after_free();
    }
    else if (!rt_strcmp(argv[1], "heap_buffer_overflow"))
    {
        heap_buffer_overflow();
    }
    else if(!rt_strcmp(argv[1], "stack_buffer_overflow"))
    {
        stack_buffer_overflow();
    }
    else if (!rt_strcmp(argv[1], "global_buffer_overflow"))
    {
        global_buffer_overflow();
    }
}

MSH_CMD_EXPORT(masan_sample, masan_sample: masan_sample<use_after_free|heap_buffer_overflow|stack_buffer_overflow|global_buffer_overflow>);
