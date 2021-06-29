/*
 * Copyright (c) 2006-2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2021-06-02     RTT       the first version
 */

#include <rtthread.h>

#define RT_DEBUG
#define LOG_TAG "asan"
#define LOG_LVL LOG_LVL_ERROR
#include <rtdbg.h>

#ifdef __cplusplus
extern "C"
#endif

static rt_int8_t shadow[(MEM_SIZE * 1024) / 8];

static void *free_quarantine_list[ASAN_FREE_QUARANTINE_LIST_SIZE];
static int free_quarantine_list_idx;

typedef enum
{
    k_is_write, /* write access */
    k_is_read,  /* read access */
} rw_mode_e;

static void __asan_report_generic_error(void)
{

      LOG_E("ASAN generic failure");
//    __asm volatile("bkpt #0"); /* stop application */
//    for (;;)
//    {
//    }
}

static uint8_t *mem_to_shadow(void *address)
{
    address -= MEM_START;
    return shadow + (((uint32_t)address) >> 3); /* divided by 8: every byte has a shadow bit */
}

static void poison_shadow_byte1_addr(void *addr)
{
    if (addr >= (void *)MEM_START && addr < (void *)(MEM_START + (MEM_SIZE * 1024)))
    {
        *mem_to_shadow(addr) |= 1 << ((uint32_t)addr & 7); /* mark memory in shadow as poisoned with shadow bit */
    }
}

static void clear_shadow_byte1_addr(void *addr)
{
    if (addr >= (void *)MEM_START && addr < (void *)(MEM_START + (MEM_SIZE * 1024)))
    {
        *mem_to_shadow(addr) &= ~(1 << ((uint32_t)addr & 7)); /* clear shadow bit: it is a valid memory */
    }
}

static rt_bool_t slow_path_check(int8_t shadow_value, void *address, size_t access_size)
{
    /* return true if access to address is poisoned */
    rt_int8_t last_accessed_byte = (((uint32_t)address) & 7) + access_size - 1;
    return (last_accessed_byte >= shadow_value);
}

static void report_error(void *address, size_t access_size, rw_mode_e mode)
{
    LOG_E("ASAN: Memory access error: addr 0x%x, %s, size: %d bytes", address, mode == k_is_read ? "read " : "write", access_size);
    //  __asm volatile("bkpt #0"); /* stop application if debugger is attached */
}

static void check_shadow(void *address, size_t access_size, rw_mode_e mode)
{
    rt_int8_t *shadow_address;
    rt_int8_t shadow_value;

    LOG_I("entry of check_shadow");
    if (address >= (void *)MEM_START && address < (void *)(MEM_START + (MEM_SIZE * 1024)))
    {
        shadow_address = (rt_int8_t *)mem_to_shadow(address);
        shadow_value = *shadow_address;

        if (shadow_value == -1)
        {
            report_error(address, access_size, mode);
        }
        else if (shadow_value != 0)

        { /* fast check: poisoned! */
            if (slow_path_check(shadow_value, address, access_size))
            {
                report_error(address, access_size, mode);
            }
        }
    }
}

void __asan_load1(void *address)
{
    LOG_I("The entry of __asan_load1");
}

void __asan_load2(void *address)
{
    LOG_I("The entry of __asan_load2");
}

void __asan_load4(void *address)
{
    LOG_I("The entry of __asan_load4");
}

void __asan_load8(void *address)
{
    LOG_I("The entry of __asan_load8");
}

void __asan_load16(void *address)
{
    LOG_I("The entry of __asan_load16");
}

void __asan_store1(void *address)
{
    LOG_I("The entry of __asan_store1");
}

void __asan_store2(void *address)
{
    LOG_I("The entry of __asan_store2");
}

void __asan_store4(void *address)
{
    LOG_I("The entry of __asan_store4");
}

void __asan_store8(void *address)
{
    LOG_I("The entry of __asan_store8");
}

void __asan_store16(void *address)
{
    LOG_I("The entry of __asan_store16");
}

void __asan_loadN(void *address)
{
    LOG_I("The entry of __asan_loadN");
}

void __asan_storeN(void *address)
{
    LOG_I("The entry of __asan_storeN");
}

void __asan_load1_noabort(void *address)
{
    LOG_I("The entry of __asan_load1_noabort");
    check_shadow(address, 1, k_is_read);
}

void __asan_load2_noabort(void *address)
{
    LOG_I("The entry of __asan_load2_noabort");
    check_shadow(address, 2, k_is_read);
}

void __asan_load4_noabort(void *address)
{
    LOG_I("The entry of __asan_load4_noabort");
    check_shadow(address, 4, k_is_read);
}

void __asan_load8_noabort(void *address)
{
    LOG_I("The entry of __asan_load8_noabort");
    check_shadow(address, 8, k_is_read);
}

void __asan_load16_noabort(void *address)
{
    LOG_I("The entry of __asan_load16_noabort");
    check_shadow(address, 16, k_is_read);
}

void __asan_store1_noabort(void *address)
{
    LOG_I("The entry of __asan_store1_noabort");
    check_shadow(address, 1, k_is_write);
}

void __asan_store2_noabort(void *address)
{
    LOG_I("The entry of __asan_store2_noabort");
    check_shadow(address, 2, k_is_write);
}

void __asan_store4_noabort(void *address)
{
    LOG_I("The entry of __asan_store4_noabort");
    check_shadow(address, 4, k_is_write);
}

void __asan_store8_noabort(void *address)
{
    LOG_I("The entry of __asan_store8_noabort");
    check_shadow(address, 8, k_is_write);
}

void __asan_store16_noabort(void *address)
{
    LOG_I("The entry of __asan_store16_noabort");
    check_shadow(address, 16, k_is_write);
}

void __asan_loadN_noabort(void *address)
{
    LOG_I("The entry of __asan_loadN_noabort");
    check_shadow(address, 0, k_is_read);
}

void __asan_storeN_noabort(void *address)
{
    LOG_I("The entry of __asan_storeN_noabort");
    check_shadow(address, 0, k_is_write);
}

void __asan_exp_load1(void *address)
{
    LOG_I("The entry of __asan_exp_load1");
}

void __asan_exp_load2(void *address)
{
    LOG_I("The entry of __asan_exp_load2");
}

void __asan_exp_load4(void *address)
{
    LOG_I("The entry of __asan_exp_load4");
}

void __asan_exp_load8(void *address)
{
    LOG_I("The entry of __asan_exp_load8");
}

void __asan_exp_load16(void *address)
{
    LOG_I("The entry of __asan_exp_load16");
}

void __asan_exp_store1(void *address)
{
    LOG_I("The entry of __asan_exp_store1");
}

void __asan_exp_store2(void *address)
{
    LOG_I("The entry of __asan_exp_store2");
}

void __asan_exp_store4(void *address)
{
    LOG_I("The entry of __asan_exp_store4");
}

void __asan_exp_store8(void *address)
{
    LOG_I("The entry of __asan_exp_store8");
}

void __asan_exp_store16(void *address)
{
    LOG_I("The entry of __asan_exp_store16");
}

void __asan_exp_loadN(void *address)
{
    LOG_I("The entry of __asan_exp_loadN");
}

void __asan_exp_storeN(void *address)
{
    LOG_I("The entry of __asan_exp_storeN");
}

//-fsanitize=address
void __asan_init_v4(void *address)
{
    LOG_I("The entry of __asan_init_v4");
}

void __asan_report_store1(void *address)
{
    LOG_I("The entry of __asan_report_store1");
    __asan_report_generic_error();
}

void __asan_report_store2(void *address)
{
    LOG_I("The entry of __asan_report_store2");
    __asan_report_generic_error();
}

void __asan_report_store4(void *address)
{
    LOG_I("The entry of __asan_report_store4");
    __asan_report_generic_error();
}

void __asan_report_store_n(void *address)
{
    LOG_I("The entry of __asan_report_store_n");
    __asan_report_generic_error();
}

void __asan_report_load1(void *address)
{
    LOG_I("The entry of __asan_report_load1");
    __asan_report_generic_error();
}

void __asan_report_load2(void *address)
{
    LOG_I("The entry of __asan_report_load2");
    __asan_report_generic_error();
}

void __asan_report_load4(void *address)
{
    LOG_I("The entry of __asan_report_load4");
    __asan_report_generic_error();
}

void __asan_report_loadn(void *address)
{
    LOG_I("The entry of __asan_report_loadn");
    __asan_report_generic_error();
}

void __asan_register_globals(void *address)
{
    LOG_I("The entry of __asan_register_globals");
    __asan_report_generic_error();
}

#ifdef CHECK_MALLOC_FREE
/* undo possible defines for malloc and free */
#ifdef rt_malloc
#undef rt_malloc
void *rt_malloc(rt_size_t nbytes); //void *malloc(size_t);
#endif
#ifdef rt_free
#undef rt_free
void rt_free(void *ptr); //void free(void*);
#endif
/*
 * rrrrrrrr  red zone border (incl. size below)
 * size
 * memory returned
 * rrrrrrrr  red zone boarder
 */

void *__asan_malloc(size_t size)
{
    //LOG_E("entry of __asan_malloc");
    void *p = rt_malloc(size + 2 * MALLOC_RED_ZONE_BORDER);
    void *q;

    q = p;

    for (int i = 0; i < MALLOC_RED_ZONE_BORDER; i++)
    {
        poison_shadow_byte1_addr(q);
        q++;
    }

    *((size_t *)(q - sizeof(size_t))) = size;

    for (int i = 0; i < size; i++)
    {
        clear_shadow_byte1_addr(q);
        q++;
    }

    for (int i = 0; i < MALLOC_RED_ZONE_BORDER; i++)
    {
        poison_shadow_byte1_addr(q);
        q++;
    }
    return p + MALLOC_RED_ZONE_BORDER;
}
#endif

#ifdef CHECK_MALLOC_FREE
void __asan_free(void *p)
{
    LOG_I("entry of __asan_free");
    size_t size = *((size_t *)(p - sizeof(size_t)));
    void *q = p;

    for (int i = 0; i < size; i++)
    {
        poison_shadow_byte1_addr(q);
        q++;
    }
    q = p - MALLOC_RED_ZONE_BORDER;

#if FREE_QUARANTINE_LIST_SIZE > 0

    free_quarantine_list[free_quarantine_list_idx] = q;
    free_quarantine_list_idx++;

    if (free_quarantine_list_idx >= FREE_QUARANTINE_LIST_SIZE)
    {
        free_quarantine_list_idx = 0;
    }

    if (free_quarantine_list[free_quarantine_list_idx] != NULL)
    {
        rt_free(free_quarantine_list[free_quarantine_list_idx]);
        free_quarantine_list[free_quarantine_list_idx] = NULL;
    }
#else
    free(q); /* free block */
#endif
}
#endif

static int __asan_init(void)
{
    int i = 0;

    LOG_I("The entry of __asan_init");

    for (i = 0; i < sizeof(shadow); i++)
    {
        shadow[i] = -1;
    }

    for (int i = 0; i < sizeof(shadow); i += 8)
    {
        poison_shadow_byte1_addr(&shadow[i]);
    }

    for (int i = 0; i < ASAN_FREE_QUARANTINE_LIST_SIZE; i++)
    {
        free_quarantine_list[i] = NULL;
    }

    free_quarantine_list_idx = 0;

    return 0;
}
INIT_BOARD_EXPORT(__asan_init);
