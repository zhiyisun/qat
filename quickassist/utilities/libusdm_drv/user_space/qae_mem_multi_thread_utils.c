/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 *  version: QAT20.L.1.1.50-00003
 *
 ***************************************************************************/
/**
 ****************************************************************************
 * @file qae_mem_multi_thread_utils.c
 *
 * This file provides for thread specific Linux user space memory allocation.
 * It uses a driver that allocates the memory in kernel memory space (to ensure
 * physically contiguous memory) and maps it to
 * user space for use by the quick assist sample code
 *
 * Each thread handles its own memory allocator information. Thread local
 * storage is used to hold all slab memory allocator information for each
 * thread.
 *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#ifndef ICP_WITHOUT_THREAD
#include <pthread.h>
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include "qae_mem.h"
#include "qae_mem_utils.h"
#include "qae_mem_user_utils.h"
#include "qae_page_table_common.h"
#include "qae_mem_utils_common.h"
#include "qae_mem_hugepage_utils.h"
#include <sys/syscall.h>

/* Check for process pid caching availibility */
#ifdef MADV_WIPEONFORK
#define CACHE_PID
#endif


#ifdef CACHE_PID
STATIC void *cache_pid = NULL;
#endif

/**************************************************************************
                                   macro
**************************************************************************/

#define QAE_MEM "/dev/usdm_drv"
/* Maximum supported alignment is 4M. */
#define QAE_MAX_PHYS_ALIGN (0x400000ULL)
/* Maximum supported allocation is 4M. */
#define QAE_MAX_ALLOC_SIZE (0x400000ULL)

#ifdef __CLANG_FORMAT__
/* clang-format off */
#endif
/* User space page table for fast virtual to physical address translation */
page_table_t g_page_table = { { { 0 } } };

#ifdef __CLANG_FORMAT__
/* clang-format on */
#endif

STATIC pthread_key_t qae_key;
static pthread_once_t qae_key_once = PTHREAD_ONCE_INIT;
static __thread int qae_mem_inited = 0;

free_page_table_fptr_t free_page_table_fptr = free_page_table;
load_addr_fptr_t load_addr_fptr = load_addr;
load_key_fptr_t load_key_fptr = load_key;

void qae_mem_destroy_t(void *thread_key);

static void qae_make_key()
{
    pthread_key_create(&qae_key, qae_mem_destroy_t);
}

const uint64_t __qae_bitmask[65] = {
    0x0000000000000000ULL, 0x0000000000000001ULL, 0x0000000000000003ULL,
    0x0000000000000007ULL, 0x000000000000000fULL, 0x000000000000001fULL,
    0x000000000000003fULL, 0x000000000000007fULL, 0x00000000000000ffULL,
    0x00000000000001ffULL, 0x00000000000003ffULL, 0x00000000000007ffULL,
    0x0000000000000fffULL, 0x0000000000001fffULL, 0x0000000000003fffULL,
    0x0000000000007fffULL, 0x000000000000ffffULL, 0x000000000001ffffULL,
    0x000000000003ffffULL, 0x000000000007ffffULL, 0x00000000000fffffULL,
    0x00000000001fffffULL, 0x00000000003fffffULL, 0x00000000007fffffULL,
    0x0000000000ffffffULL, 0x0000000001ffffffULL, 0x0000000003ffffffULL,
    0x0000000007ffffffULL, 0x000000000fffffffULL, 0x000000001fffffffULL,
    0x000000003fffffffULL, 0x000000007fffffffULL, 0x00000000ffffffffULL,
    0x00000001ffffffffULL, 0x00000003ffffffffULL, 0x00000007ffffffffULL,
    0x0000000fffffffffULL, 0x0000001fffffffffULL, 0x0000003fffffffffULL,
    0x0000007fffffffffULL, 0x000000ffffffffffULL, 0x000001ffffffffffULL,
    0x000003ffffffffffULL, 0x000007ffffffffffULL, 0x00000fffffffffffULL,
    0x00001fffffffffffULL, 0x00003fffffffffffULL, 0x00007fffffffffffULL,
    0x0000ffffffffffffULL, 0x0001ffffffffffffULL, 0x0003ffffffffffffULL,
    0x0007ffffffffffffULL, 0x000fffffffffffffULL, 0x001fffffffffffffULL,
    0x003fffffffffffffULL, 0x007fffffffffffffULL, 0x00ffffffffffffffULL,
    0x01ffffffffffffffULL, 0x03ffffffffffffffULL, 0x07ffffffffffffffULL,
    0x0fffffffffffffffULL, 0x1fffffffffffffffULL, 0x3fffffffffffffffULL,
    0x7fffffffffffffffULL, 0xffffffffffffffffULL,
};

/* bitmap_read function
 * reads a 64-bit window from a BITMAP_LENx64-bit bitmap
 * starting from window_pos (0 <-> BITMAP_LENx64 -1)
 * map points to the BITMAP_LENx64 bit map area
 * returns the 64-bit window from the BITMAP_LENx64 bitmap.
 * Each bit represents a 1k block in the 2 Meg buffer
 */
STATIC uint64_t bitmap_read(uint64_t *map, size_t window_pos)
{
    uint64_t quad_word_window = 0ULL;
    uint64_t next_quad_word = 0ULL;
    size_t quad_word_pos = 0;
    size_t bit_pos = 0;

    quad_word_pos = window_pos / QWORD_WIDTH;

    if (quad_word_pos >= BITMAP_LEN)
    {
        return QWORD_ALL_ONE;
    }
    bit_pos = window_pos % QWORD_WIDTH;

    quad_word_window = map[quad_word_pos];

    if (0 == bit_pos)
    {
        return quad_word_window;
    }

    /* it is safe to read the next quad word because
     * there is always a barrier at the end */
    next_quad_word = map[quad_word_pos + 1];

    quad_word_window >>= bit_pos;
    next_quad_word <<= QWORD_WIDTH - bit_pos;
    quad_word_window |= next_quad_word;

    return quad_word_window;
}

/* mem_alloc function
 * mem_alloc allocates memory with min. size = UNIT_SIZE
 * block_ctrl points to a block_ctrl_t structure with virtual address
 * size is the requested number of bytes
 * minimum allocation size is UNIT_SIZE
 * returns a pointer to the newly allocated block
 * input: block_ctrl - pointer to the memory control block
 *        size - size requested in bytes
 * output: pointer to the allocated area
 */
API_LOCAL
void *__qae_mem_alloc(block_ctrl_t *block_ctrl, size_t size, size_t align)
{
    uint64_t *bitmap = NULL;
    size_t window_pos = 0;
    void *retval = NULL;
    size_t blocks_found = 0;
    uint64_t bitmap_window = 0ULL;
    size_t blocks_required = 0ULL;
    size_t first_block = 0;
    size_t width = 0;
    size_t width_ones = 0;

    if (NULL == block_ctrl || 0 == size)
    {
        CMD_ERROR(" %s:%d invalid control block or size provided "
                  "block_ctrl = %p and size = %zu \n",
                  __func__,
                  __LINE__,
                  block_ctrl,
                  size);
        return retval;
    }

    bitmap = block_ctrl->bitmap;

    blocks_required = div_round_up(size, UNIT_SIZE);

    window_pos = 0;
    first_block = window_pos;

    do
    {
        /* read 64-bit bitmap window from window_pos (0-BITMAP_LEN*64) */
        bitmap_window = bitmap_read(bitmap, window_pos);
        /* find number of contiguous 0s from right */
        width = mem_ctzll(bitmap_window);

        /* increment number of blocks found with number of contig. 0s
           in bitmap window */
        blocks_found += width;
        /* check if a fit is found */
        if (blocks_found >= blocks_required)
        {
            /* calculate return address from virtual address and
               first block number */
            retval = (uint8_t *)(block_ctrl) + first_block * UNIT_SIZE;
            if (first_block + blocks_required > BITMAP_LEN * QWORD_WIDTH)
            {
                CMD_ERROR("%s:%d Allocation error - Required blocks exceeds "
                          "bitmap window. Block index = %zu, Blocks required"
                          " = %zu and Bitmap window = %ld \n",
                          __func__,
                          __LINE__,
                          first_block,
                          blocks_required,
                          (BITMAP_LEN * QWORD_WIDTH));
                return NULL;
            }
            /* save length in the reserved area right after the bitmap  */
            block_ctrl->sizes[first_block] = (uint16_t)blocks_required;
            /* set bit maps from bit position (0<->BITMAP_LEN*64 -1) =
             * first_block(0<->BITMAP_LEN*64-1)
             * with blocks_required length in bitmap
             */
            set_bitmap(bitmap, first_block, blocks_required);
            break;
        }
        else
        {
            /* Did not find fit. Check if bitmap_window has at least a 1*/
            if (bitmap_window)
            {
                /* This field of contiguous 0s is not big enough, so need
                 * to jump past those 0s and the adjacent 1s and
                 * restart the search at next 0.
                 */
                /* move past the zeros to where the 1s start */
                bitmap_window >>= width;
                /* count the 1s */
                width_ones = mem_ctzll(~bitmap_window);
                /* Set position from which to read next window */
                window_pos += width + width_ones;
                /* Align position if necessary*/
                if (align && window_pos % align)
                {
                    window_pos += align - window_pos % align;
                }
                /* Reset previous search results */
                first_block = window_pos;
                blocks_found = 0;
            }
            else
            {
                /* bit field of 0s is contiguous, but fit not found yet
                 * move window_pos an search more 0s */
                window_pos += width;
            }
        }
    } while (window_pos < BITMAP_LEN * QWORD_WIDTH);
    return retval;
}

/*
 * deallocates previously allocated blocks
 * block_ctrl is a pointer to block_ctrl_t structure
 * block is a result from a previous mem_alloc call
 * secure_free is a boolean to perform memory free secured or not
 */
API_LOCAL
bool __qae_mem_free(block_ctrl_t *block_ctrl, void *block, bool secure_free)
{
    size_t first_block = 0;
    uint32_t length = 0;
    uint8_t *start_of_block = block;
    uint64_t *bitmap = NULL;

    if (NULL == block_ctrl || NULL == block)
    {
        CMD_ERROR("%s:%d One of the parameters is NULL. block_ctrl = %p "
                  "block = %p\n",
                  __func__,
                  __LINE__,
                  block_ctrl,
                  block);
        return false;
    }

    if ((uintptr_t)block % UNIT_SIZE)
    {
        CMD_ERROR("%s:%d Block address(%p) must be multiple of Unit size(%d)\n",
                  __func__,
                  __LINE__,
                  block,
                  UNIT_SIZE);
        return false;
    }

    bitmap = block_ctrl->bitmap;

    /* find start of block in block numbers using the address of start of
     * buffer and block retrieve first_block and length of block from integer
     * at the start of block
     */
    first_block =
        ((uintptr_t)start_of_block - (uintptr_t)block_ctrl) / UNIT_SIZE;
    length = block_ctrl->sizes[first_block];

    if (!length)
    {
        CMD_ERROR("%s:%d Invalid block address provided - "
                  "Block index = %zu. "
                  "Possibly double free.\n",
                  __func__,
                  __LINE__,
                  first_block);

        return false;
    }

    if (length + first_block > BITMAP_LEN * QWORD_WIDTH)
    {
        CMD_ERROR("%s:%d Invalid block address provided - "
                  "block length exceeds bitmap window. block index = %zu "
                  "and block length: %d\n",
                  __func__,
                  __LINE__,
                  first_block,
                  length);
        return false;
    }

    block_ctrl->sizes[first_block] = 0;
    /* clear bitmap from bitmap position (0<->BITMAP_LEN*64 - 1) for length*/
    clear_bitmap(bitmap, first_block, length);

    if (secure_free)
    {
#ifndef ICP_DISABLE_SECURE_MEM_FREE
        qae_memzero_explicit(block, length * UNIT_SIZE);
#endif
    }

    return true;
}
API_LOCAL
dev_mem_info_t *__qae_userMemLookupBySize(size_t size,
                                          int node,
                                          void **block,
                                          const size_t align,
                                          qae_mem_info_t *tls_ptr)
{
    dev_mem_info_t *pCurr = NULL;
    size_t link_num = 0;

    for (pCurr = tls_ptr->pUserMemListHead; pCurr != NULL;
         pCurr = pCurr->pNext_user)
    {
        if (tls_ptr->g_strict_node && (pCurr->nodeId != node))
        {
            continue;
        }
        *block = __qae_mem_alloc((block_ctrl_t *)pCurr, size, align);
        if (NULL != *block)
        {
            return pCurr;
        }
        /* Prevent from visiting whole chain, because after the first
         * several node, the chance to get one is very small.
         * Another consideration is to prevent new allocation from old
         * link, so that the old link could be released
         */
        link_num++;
        if (link_num >= tls_ptr->g_max_lookup_num)
        {
            break;
        }
    }
    return NULL;
}

/**************************************
 * Memory functions
 *************************************/
void *qaeMemAlloc(size_t memsize)
{
    void *memPtr = NULL;
    memPtr = calloc(memsize, sizeof(uint8_t));
    return memPtr;
}

void qaeMemFree(void **ptr)
{
    if ((!ptr) || !(*ptr))
    {
        CMD_ERROR("%s:%d Trying to Free NULL Pointer\n", __func__, __LINE__);
        return;
    }
    free(*ptr);
    *ptr = NULL;
}

/*translate a virtual address to a physical address */
uint64_t qaeVirtToPhysNUMA(void *pVirtAddress)
{
    return load_addr_fptr(&g_page_table, pVirtAddress);
}

/* translate a physical address to a virtual address */
void *qaePhysToVirtNUMA(uint64_t physAddress)
{
    dev_mem_info_t *slab;
    uintptr_t offset;
    void *ret = NULL;
    qae_mem_info_t *tls_ptr;
    tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key);
    /* find slab from physical address without using hash lookup */
    for (slab = tls_ptr->pUserMemListHead; slab != NULL;
         slab = slab->pNext_user)
    {
        offset = (uintptr_t)physAddress - (uintptr_t)slab->phy_addr;
        if (offset < slab->size)
        {
            ret = (void *)((uintptr_t)slab->virt_addr + offset);
            break;
        }
    }
    return ret;
}

void qaeAtFork()
{
    return;
}

API_LOCAL
void __qae_free_slab(const int fd,
                     dev_mem_info_t *slab,
                     qae_mem_info_t *tls_ptr)
{
    dev_mem_info_t memInfo;
    int ret = 0;

    del_slab_from_hash(slab, tls_ptr);

    memcpy(&memInfo, slab, sizeof(dev_mem_info_t));
    /* Need to disconnect from orignal chain */
    ret = qae_munmap(memInfo.virt_addr, memInfo.size);
    if (ret)
    {
        CMD_ERROR("%s:%d munmap failed, ret = %d\n", __func__, __LINE__, ret);
    }
    if (LARGE == memInfo.type)
    {
        ret = qae_munmap(slab, getpagesize());
        if (ret)
        {
            CMD_ERROR(
                "%s:%d munmap failed, ret = %d\n", __func__, __LINE__, ret);
        }
    }

    __qae_finish_free_slab(fd, &memInfo);
}

API_LOCAL
dev_mem_info_t *__qae_find_slab(const int fd,
                                const size_t size,
                                const int node,
                                void **addr,
                                const size_t align,
                                qae_mem_info_t *tls_ptr)
{
    dev_mem_info_t *slab =
        __qae_userMemLookupBySize(size, node, addr, align, tls_ptr);

    if (NULL == slab)
    {
        slab = pop_slab(node, tls_ptr);
        if (NULL != slab)
        {
            *addr =
                init_slab_and_alloc((block_ctrl_t *)slab, size, align, tls_ptr);
            if (NULL == *addr)
            {
                CMD_ERROR("%s:%d Memory allocation failed Virtual address: %p "
                          " Size: %zu \n",
                          __func__,
                          __LINE__,
                          slab,
                          size);
                __qae_free_slab(fd, slab, tls_ptr);
                return NULL;
            }
        }
    }
    return slab;
}

static void qae_mem_init_t(void)
{
    qae_mem_info_t *tls_ptr;
    pthread_once(&qae_key_once, qae_make_key);

    if ((tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key)) == NULL)
    {
        tls_ptr = malloc(sizeof(qae_mem_info_t));
        /* Reset all control structures. */
        memset(tls_ptr, 0, sizeof(qae_mem_info_t));
        pthread_setspecific(qae_key, (void *)tls_ptr);
    }

    tls_ptr->g_strict_node = 1;
    tls_ptr->g_max_lookup_num = 10;
    tls_ptr->g_max_cache = 0x800000;
    tls_ptr->thd_process_id = syscall(__NR_gettid);

    qae_mem_inited = 1;
}

int32_t qaeMemInit()
{
/* Check if it is a new process or child. */
#ifdef CACHE_PID
    const int is_new_pid =
        cache_pid == NULL || (cache_pid != NULL && *((pid_t *)cache_pid) == 0);
#else
    const int is_new_pid = check_pid();
#endif
    int32_t status = 0;

    if (!is_new_pid && g_fd > 0)
    {
        return status;
    }

    qae_key = 0;
    qae_mem_inited = 0;
    qae_key_once = PTHREAD_ONCE_INIT;
    g_fd = qae_open(QAE_MEM, O_RDWR);
    if (g_fd < 0)
    {
        CMD_ERROR("%s:%d Unable to initialize memory file handle %s \n",
                  __func__,
                  __LINE__,
                  QAE_MEM);
        return -ENOENT;
    }
    free_page_table_fptr(&g_page_table);
    memset(&g_page_table, 0, sizeof(g_page_table));

#ifdef CACHE_PID
    /* Cache pid */
    if (!cache_pid)
    {
        int page_size = getpagesize();

        cache_pid = qae_mmap(NULL,
                             page_size,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANON,
                             -1,
                             0);
        if (cache_pid == NULL)
        {
            CMD_ERROR(
                "%s:%d Unable to mmap aligned memory \n", __func__, __LINE__);
            return -ENOMEM;
        }

        if (qae_madvise(cache_pid, page_size, MADV_WIPEONFORK))
        {

            CMD_ERROR(
                "%s:%d Unable to update page properties\n", __func__, __LINE__);
            qae_munmap(cache_pid, page_size);
            close(g_fd);
            cache_pid = NULL;
            return -ENOMEM;
        }
    }

    *((pid_t *)cache_pid) = getpid();
#endif

    if (__qae_init_hugepages(g_fd))
    {
        close(g_fd);
        return -EIO;
    }
    return status;
}

API_LOCAL
void __qae_destroyList(const int fd, dev_mem_info_t *pList, void *thread_key)
{
    dev_mem_info_t *pCurr = pList;

    while (pCurr)
    {
        dev_mem_info_t *next = pCurr->pNext_user;
        __qae_free_slab(fd, pCurr, (qae_mem_info_t *)thread_key);
        pCurr = next;
    }
}

API_LOCAL
void __qae_reset_cache(const int fd, void *thread_key)
{

    dev_mem_info_t *slab = NULL;
    do
    {
        slab = pop_slab(NUMA_ANY_NODE, (qae_mem_info_t *)thread_key);
        if (NULL != slab)
            __qae_free_slab(fd, slab, (qae_mem_info_t *)thread_key);
    } while (slab != NULL);
}

void qaeMemDestroy(void)
{
    int ret = 0;
    qae_mem_info_t *tls_ptr = NULL;

    free_page_table_fptr(&g_page_table);
#ifdef CACHE_PID
    if (cache_pid != NULL)
    {
        ret = qae_munmap(cache_pid, getpagesize());
        if (ret)
        {
            CMD_ERROR("%s:%d munmap call for cache failed, ret = %d\n",
                      __func__,
                      __LINE__,
                      ret);
        }
        cache_pid = NULL;
    }
#endif
    tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key);
    if (tls_ptr && qae_mem_inited)
    {
        __qae_reset_cache(g_fd, (void *)tls_ptr);
        __qae_destroyList(g_fd, tls_ptr->pUserMemListHead, (void *)tls_ptr);
        __qae_destroyList(
            g_fd, tls_ptr->pUserLargeMemListHead, (void *)tls_ptr);
        free(tls_ptr);
        pthread_setspecific(qae_key, NULL);
    }

    if (g_fd > 0)
    {
        ret = mem_ioctl(g_fd, DEV_MEM_IOC_RELEASE, NULL);
        if (ret)
        {
            CMD_ERROR("%s:%d ioctl call for mem release failed, ret = %d\n",
                      __func__,
                      __LINE__,
                      ret);
        }
        close(g_fd);
        g_fd = -1;
    }
    qae_mem_inited = 0;
    pthread_key_delete(qae_key);
}

void qae_mem_destroy_t(void *thread_key)
{
    qae_mem_info_t *tls_ptr;
    tls_ptr = (qae_mem_info_t *)thread_key;
    /* release all control buffers */
    __qae_reset_cache(g_fd, thread_key);
    __qae_destroyList(g_fd, tls_ptr->pUserMemListHead, thread_key);
    __qae_destroyList(g_fd, tls_ptr->pUserLargeMemListHead, thread_key);

    free(thread_key);
    qae_mem_inited = 0;
}

API_LOCAL
void *__qae_alloc_addr(size_t size,
                       const int node,
                       const size_t phys_alignment_byte)
{
    dev_mem_info_t *p_ctrl_blk = NULL;
    void *pVirtAddress = NULL;
    size_t allocate_pages = 0;
    enum slabType mem_type = SMALL;
    qae_mem_info_t *tls_ptr;
    tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key);

    const size_t phys_align_unit = phys_alignment_byte / UNIT_SIZE;
    const size_t reserved = div_round_up(sizeof(block_ctrl_t), UNIT_SIZE);
    /* calculate units needed */
    const size_t requested_pages = div_round_up(size, UNIT_SIZE) + reserved;

    if (tls_ptr == NULL)
    {
        CMD_ERROR("error, unable to initialise slab allocator\n");
        return NULL;
    }

    if (requested_pages > QAE_NUM_PAGES_PER_ALLOC * QAE_PAGE_SIZE / UNIT_SIZE ||
        phys_alignment_byte >= QAE_NUM_PAGES_PER_ALLOC * QAE_PAGE_SIZE)
    {
        mem_type = LARGE;
        /* Huge page and Large memory are mutually exclusive
         * Since Large slabs are NOT 2 MB aligned, but huge
         * pages are always 2 MB aligned.
         */
        if (__qae_hugepage_enabled())
            return NULL;

        size = MAX(size, phys_alignment_byte);
        allocate_pages = div_round_up(size, UNIT_SIZE);
    }
    else
    {
        allocate_pages = QAE_NUM_PAGES_PER_ALLOC * QAE_PAGE_SIZE / UNIT_SIZE;
        if (__qae_hugepage_enabled())
            mem_type = HUGE_PAGE;

        p_ctrl_blk = __qae_find_slab(
            g_fd, size, node, &pVirtAddress, phys_align_unit, tls_ptr);

        if (p_ctrl_blk)
        {
            p_ctrl_blk->allocations += 1;
            return pVirtAddress;
        }
    }

    /* Try to allocate memory as much as possible */
    p_ctrl_blk = __qae_alloc_slab(g_fd,
                                  allocate_pages * UNIT_SIZE,
                                  phys_alignment_byte,
                                  node,
                                  mem_type,
                                  tls_ptr);
    if (NULL == p_ctrl_blk)
        return NULL;

    store_mmap_range(&g_page_table,
                     p_ctrl_blk->virt_addr,
                     p_ctrl_blk->phy_addr,
                     p_ctrl_blk->size,
                     __qae_hugepage_enabled());

    if (LARGE == mem_type)
    {
        p_ctrl_blk->allocations = 1;

        ADD_ELEMENT_TO_HEAD_LIST(p_ctrl_blk,
                                 tls_ptr->pUserLargeMemListHead,
                                 tls_ptr->pUserLargeMemListTail,
                                 _user);

        pVirtAddress = p_ctrl_blk->virt_addr;
    }
    else
    {
        p_ctrl_blk->allocations = 1;

        if ((uintptr_t)p_ctrl_blk->virt_addr % QAE_PAGE_SIZE)
        {
            CMD_ERROR("%s:%d Bad virtual address alignment %lux %x %lux\n",
                      __func__,
                      __LINE__,
                      (uintptr_t)p_ctrl_blk->virt_addr,
                      QAE_NUM_PAGES_PER_ALLOC,
                      QAE_PAGE_SIZE);
            __qae_free_slab(g_fd, p_ctrl_blk, tls_ptr);

            return NULL;
        }
        pVirtAddress = init_slab_and_alloc(
            (block_ctrl_t *)p_ctrl_blk, size, phys_align_unit, tls_ptr);
        if (NULL == pVirtAddress)
        {
            CMD_ERROR("%s:%d Memory allocation failed Virtual address: %p "
                      " Size: %zu \n",
                      __func__,
                      __LINE__,
                      p_ctrl_blk,
                      size);
            __qae_free_slab(g_fd, p_ctrl_blk, tls_ptr);

            return NULL;
        }
    }
    return pVirtAddress;
}

void *qaeMemAllocNUMA(size_t size, int node, size_t phys_alignment_byte)
{
    void *pVirtAddress = NULL;

    if (!size)
    {
        CMD_ERROR("%s:%d Size cannot be zero \n", __func__, __LINE__);
        return NULL;
    }

    if (size > QAE_MAX_ALLOC_SIZE)
    {
        CMD_ERROR("%s:%d Size cannot exceed 4M \n", __func__, __LINE__);
        return NULL;
    }

    if (!phys_alignment_byte || phys_alignment_byte > QAE_MAX_PHYS_ALIGN ||
        (phys_alignment_byte & (phys_alignment_byte - 1)))
    {
        CMD_ERROR("%s:%d Invalid alignment parameter %zu. It must be non zero, "
                  "not more than %llu and multiple of 2 \n",
                  __func__,
                  __LINE__,
                  phys_alignment_byte,
                  QAE_MAX_PHYS_ALIGN);
        return NULL;
    }

    if (0 != qaeMemInit())
        return NULL;

    if (!qae_mem_inited)
    {
        qae_mem_init_t();
    }

    pVirtAddress = __qae_alloc_addr(size, node, phys_alignment_byte);
    return pVirtAddress;
}

API_LOCAL
void __qae_free_addr(void **p_va, bool secure_free)
{
    dev_mem_info_t *p_ctrl_blk = NULL;
    qae_mem_info_t *tls_ptr;

    tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key);
    if (!tls_ptr)
    {
        CMD_ERROR("%s:%d No memory alloc info found \n", __func__, __LINE__);
        return;
    }

    if ((p_ctrl_blk = find_slab_in_hash(*p_va, tls_ptr)) == NULL)
    {
        CMD_ERROR("%s:%d Unable to free as lookup failed on address (%p) "
                  "provided \n",
                  __func__,
                  __LINE__,
                  *p_va);
        return;
    }
    if (SMALL == p_ctrl_blk->type || HUGE_PAGE == p_ctrl_blk->type)
    {
        if (__qae_mem_free((block_ctrl_t *)p_ctrl_blk, *p_va, secure_free))
        {
            p_ctrl_blk->allocations -= 1;
        }
        else
        {
            /*Skip push_slab(p_ctrl_blk)) and return when mem_free fails */
            CMD_ERROR("%s:%d mem_free returned false  (%p) "
                      "provided \n",
                      __func__,
                      __LINE__,
                      *p_va);
            *p_va = NULL;
            return;
        }
        if (p_ctrl_blk->allocations)
        {
            *p_va = NULL;
            return;
        }

        REMOVE_ELEMENT_FROM_LIST(p_ctrl_blk,
                                 tls_ptr->pUserMemListHead,
                                 tls_ptr->pUserMemListTail,
                                 _user);
        if (0 != push_slab(p_ctrl_blk, tls_ptr))
            __qae_free_slab(g_fd, p_ctrl_blk, tls_ptr);
    }
    else
    {
        REMOVE_ELEMENT_FROM_LIST(p_ctrl_blk,
                                 tls_ptr->pUserLargeMemListHead,
                                 tls_ptr->pUserLargeMemListTail,
                                 _user);
        __qae_free_slab(g_fd, p_ctrl_blk, tls_ptr);
    }
    *p_va = NULL;
}

/* __qae_memFreeNUMA function
 * Frees memory pointed by ptr.
 * ptr refers to memory allocated by qaeMemAllocNUMA function.
 * secure_free is a boolean to perform memory free secured or not.
 */
API_LOCAL
void __qae_memFreeNUMA(void **ptr, bool secure_free)
{

    if (NULL == ptr)
    {
        CMD_ERROR(
            "%s:%d Input parameter cannot be NULL \n", __func__, __LINE__);
        return;
    }
    if (NULL == *ptr)
    {
        CMD_ERROR(
            "%s:%d Address to be freed cannot be NULL \n", __func__, __LINE__);
        return;
    }
    __qae_free_addr(ptr, secure_free);

    return;
}

void qaeMemFreeNUMA(void **ptr)
{
    __qae_memFreeNUMA(ptr, true);
    return;
}

void qaeMemFreeNonZeroNUMA(void **ptr)
{
    __qae_memFreeNUMA(ptr, false);
    return;
}
