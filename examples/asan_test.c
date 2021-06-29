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

#define THREAD_STACK_SIZE   1024
#define THREAD_PRIORITY     20
#define THREAD_TIMESLICE    10

static rt_thread_t masan_pid = RT_NULL;
static rt_uint16_t arr[] = {1,2,3};
static rt_uint16_t *p = &arr[0];

static void test1(void)
{
  p = rt_malloc(16);
  rt_free(p);
  arr[0] = *p;
  *p = 0;  /* BOOM: access to released memory */
}

static int test2(void)
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
  return i+c;
}

static void test3(void)
{
    char a[3] = {'#'};
    a[6] = '*';

}

static void ASAN_Test(void *param)
{
  test1();
  test2();
  test3();
}

int masan_sample(void)
{
    masan_pid = rt_thread_create("masan_sample",
                            ASAN_Test, RT_NULL,
                            THREAD_STACK_SIZE,
                            THREAD_PRIORITY, THREAD_TIMESLICE);

    if (masan_pid != RT_NULL)
        rt_thread_startup(masan_pid);
    return 0;
}

MSH_CMD_EXPORT(masan_sample, masan_sample);
