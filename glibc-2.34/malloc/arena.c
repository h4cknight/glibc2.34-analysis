/* Malloc implementation for multiple threads without lock contention.
   Copyright (C) 2001-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Wolfram Gloger <wg@malloc.de>, 2001.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, see <https://www.gnu.org/licenses/>.  */

#include <stdbool.h>

#if HAVE_TUNABLES
# define TUNABLE_NAMESPACE malloc
#endif
#include <elf/dl-tunables.h>

/* Compile-time constants.  */

#define HEAP_MIN_SIZE (32 * 1024)
#ifndef HEAP_MAX_SIZE
# ifdef DEFAULT_MMAP_THRESHOLD_MAX
#  define HEAP_MAX_SIZE (2 * DEFAULT_MMAP_THRESHOLD_MAX)
# else
#  define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */
# endif
#endif

/* HEAP_MIN_SIZE and HEAP_MAX_SIZE limit the size of mmap()ed heaps
   that are dynamically created for multi-threaded programs.  The
   maximum size must be a power of two, for fast determination of
   which heap belongs to a chunk.  It should be much larger than the
   mmap threshold, so that requests with a size just below that
   threshold can be fulfilled without creating too many heaps.  */

/***************************************************************************/

#define top(ar_ptr) ((ar_ptr)->top)

/* A heap is a single contiguous memory region holding (coalesceable)
   malloc_chunks.  It is allocated with mmap() and always starts at an
   address aligned to HEAP_MAX_SIZE.  */

typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;

/* Get a compile-time error if the heap_info padding is not correct
   to make alignment work as expected in sYSMALLOc.  */
extern int sanity_check_heap_info_alignment[(sizeof (heap_info)
                                             + 2 * SIZE_SZ) % MALLOC_ALIGNMENT
                                            ? -1 : 1];

/* Thread specific data.  */

static __thread mstate thread_arena attribute_tls_model_ie;

/* Arena free list.  free_list_lock synchronizes access to the
   free_list variable below, and the next_free and attached_threads
   members of struct malloc_state objects.  No other locks must be
   acquired after free_list_lock has been acquired.  */

__libc_lock_define_initialized (static, free_list_lock);
#if IS_IN (libc)
static size_t narenas = 1;
#endif
static mstate free_list;

/* list_lock prevents concurrent writes to the next member of struct
   malloc_state objects.

   Read access to the next member is supposed to synchronize with the
   atomic_write_barrier and the write to the next member in
   _int_new_arena.  This suffers from data races; see the FIXME
   comments in _int_new_arena and reused_arena.

   list_lock also prevents concurrent forks.  At the time list_lock is
   acquired, no arena lock must have been acquired, but it is
   permitted to acquire arena locks subsequently, while list_lock is
   acquired.  */
__libc_lock_define_initialized (static, list_lock);

/* Already initialized? */
static bool __malloc_initialized = false;

/**************************************************************************/


/* arena_get() acquires an arena and locks the corresponding mutex.
   First, try the one last locked successfully by this thread.  (This
   is the common case and handled with a macro for speed.)  Then, loop
   once over the circularly linked list of arenas.  If no arena is
   readily available, create a new one.  In this latter case, `size'
   is just a hint as to how much memory will be required immediately
   in the new arena. */
//获取arena并锁住它，通常用于多线程环境下
//首先尝试通过__thread mstate thread_arena 获取；
//如果没有获取到则通过arena_get2获取
#define arena_get(ptr, size) do { \
      ptr = thread_arena;						      \
      arena_lock (ptr, size);						      \
  } while (0)

#define arena_lock(ptr, size) do {					      \
      if (ptr)								      \
        __libc_lock_lock (ptr->mutex);					      \
      else								      \
        ptr = arena_get2 ((size), NULL);				      \
  } while (0)

/* find the heap and corresponding arena for a given ptr */

#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))//说明heap_info是一个vma（HEAP_MAX_SIZE对齐了）的起始地址；这么说可能不一定准确，若是两个堆段在一起，且权限一致的话这就只有一个vma，当然了还是两个heap区域
#define arena_for_chunk(ptr) \
  (chunk_main_arena (ptr) ? &main_arena : heap_for_ptr (ptr)->ar_ptr)//获取main arena的地址或者ptr所对应的heap_info中记录的ar_ptr，这种操作感觉表明了一个信息：同一个arena的所有heap_info的ar_ptr都相同


/**************************************************************************/

/* atfork support.  */

/* The following three functions are called around fork from a
   multi-threaded process.  We do not use the general fork handler
   mechanism to make sure that our handlers are the last ones being
   called, so that other fork handlers can use the malloc
   subsystem.  */

void
__malloc_fork_lock_parent (void)
{
  if (!__malloc_initialized)
    return;

  /* We do not acquire free_list_lock here because we completely
     reconstruct free_list in __malloc_fork_unlock_child.  */

  __libc_lock_lock (list_lock);

  for (mstate ar_ptr = &main_arena;; )
    {
      __libc_lock_lock (ar_ptr->mutex);
      ar_ptr = ar_ptr->next;
      if (ar_ptr == &main_arena)
        break;
    }
}

void
__malloc_fork_unlock_parent (void)
{
  if (!__malloc_initialized)
    return;

  for (mstate ar_ptr = &main_arena;; )
    {
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = ar_ptr->next;
      if (ar_ptr == &main_arena)
        break;
    }
  __libc_lock_unlock (list_lock);
}

void
__malloc_fork_unlock_child (void)
{
  if (!__malloc_initialized)
    return;

  /* Push all arenas to the free list, except thread_arena, which is
     attached to the current thread.  */
  __libc_lock_init (free_list_lock);
  if (thread_arena != NULL)
    thread_arena->attached_threads = 1;
  free_list = NULL;
  for (mstate ar_ptr = &main_arena;; )
    {
      __libc_lock_init (ar_ptr->mutex);
      if (ar_ptr != thread_arena)
        {
	  /* This arena is no longer attached to any thread.  */
	  ar_ptr->attached_threads = 0;
          ar_ptr->next_free = free_list;//next_free仅仅包含freelist，next既包含free，也包含非free
          free_list = ar_ptr;
        }
      ar_ptr = ar_ptr->next;
      if (ar_ptr == &main_arena)//说明绕了一圈了
        break;
    }

  __libc_lock_init (list_lock);
}

#if HAVE_TUNABLES
# define TUNABLE_CALLBACK_FNDECL(__name, __type) \
static inline int do_ ## __name (__type value);				      \
static void									      \
TUNABLE_CALLBACK (__name) (tunable_val_t *valp)				      \
{									      \
  __type value = (__type) (valp)->numval;				      \
  do_ ## __name (value);						      \
}

TUNABLE_CALLBACK_FNDECL (set_mmap_threshold, size_t)
TUNABLE_CALLBACK_FNDECL (set_mmaps_max, int32_t)
TUNABLE_CALLBACK_FNDECL (set_top_pad, size_t)
TUNABLE_CALLBACK_FNDECL (set_perturb_byte, int32_t)
TUNABLE_CALLBACK_FNDECL (set_trim_threshold, size_t)
TUNABLE_CALLBACK_FNDECL (set_arena_max, size_t)
TUNABLE_CALLBACK_FNDECL (set_arena_test, size_t)
#if USE_TCACHE
TUNABLE_CALLBACK_FNDECL (set_tcache_max, size_t)
TUNABLE_CALLBACK_FNDECL (set_tcache_count, size_t)
TUNABLE_CALLBACK_FNDECL (set_tcache_unsorted_limit, size_t)
#endif
TUNABLE_CALLBACK_FNDECL (set_mxfast, size_t)
#else
/* Initialization routine. */
#include <string.h>
extern char **_environ;

static char *
next_env_entry (char ***position)
{
  char **current = *position;
  char *result = NULL;

  while (*current != NULL)
    {
      if (__builtin_expect ((*current)[0] == 'M', 0)
          && (*current)[1] == 'A'
          && (*current)[2] == 'L'
          && (*current)[3] == 'L'
          && (*current)[4] == 'O'
          && (*current)[5] == 'C'
          && (*current)[6] == '_')
        {
          result = &(*current)[7];

          /* Save current position for next visit.  */
          *position = ++current;

          break;
        }

      ++current;
    }

  return result;
}
#endif


#ifdef SHARED
extern struct dl_open_hook *_dl_open_hook;
libc_hidden_proto (_dl_open_hook);
#endif

#if USE_TCACHE
static void tcache_key_initialize (void);
#endif

static void
ptmalloc_init (void)
{
  if (__malloc_initialized)
    return;

  __malloc_initialized = true;

#if USE_TCACHE
  //随机初始化tcache_key
  tcache_key_initialize ();
#endif
//global -g USE_MTAG 搜索，发现此宏和体系架构aarch64相关，暂不分析
#ifdef USE_MTAG
  if ((TUNABLE_GET_FULL (glibc, mem, tagging, int32_t, NULL) & 1) != 0)
    {
      /* If the tunable says that we should be using tagged memory
	 and that morecore does not support tagged regions, then
	 disable it.  */
      if (__MTAG_SBRK_UNTAGGED)
	__always_fail_morecore = true;

      mtag_enabled = true;
      mtag_mmap_flags = __MTAG_MMAP_FLAGS;
    }
#endif

#if defined SHARED && IS_IN (libc)
  /* In case this libc copy is in a non-default namespace, never use
     brk.  Likewise if dlopened from statically linked program.  The
     generic sbrk implementation also enforces this, but it is not
     used on Hurd.  */
  if (!__libc_initial)
    __always_fail_morecore = true;
#endif
  //Thread specific data.  定义时thread_arena有__thread 前缀，表明线程私有变量
  //main_arena是一个libc.so的一个静态全局变量
  thread_arena = &main_arena;
  //这里初始化main_arena
  malloc_init_state (&main_arena);
  //初始化一些变量
#if HAVE_TUNABLES
  TUNABLE_GET (top_pad, size_t, TUNABLE_CALLBACK (set_top_pad));
  TUNABLE_GET (perturb, int32_t, TUNABLE_CALLBACK (set_perturb_byte));
  TUNABLE_GET (mmap_threshold, size_t, TUNABLE_CALLBACK (set_mmap_threshold));
  TUNABLE_GET (trim_threshold, size_t, TUNABLE_CALLBACK (set_trim_threshold));
  TUNABLE_GET (mmap_max, int32_t, TUNABLE_CALLBACK (set_mmaps_max));
  TUNABLE_GET (arena_max, size_t, TUNABLE_CALLBACK (set_arena_max));
  TUNABLE_GET (arena_test, size_t, TUNABLE_CALLBACK (set_arena_test));
# if USE_TCACHE
  TUNABLE_GET (tcache_max, size_t, TUNABLE_CALLBACK (set_tcache_max));
  TUNABLE_GET (tcache_count, size_t, TUNABLE_CALLBACK (set_tcache_count));
  TUNABLE_GET (tcache_unsorted_limit, size_t,
	       TUNABLE_CALLBACK (set_tcache_unsorted_limit));
# endif
  TUNABLE_GET (mxfast, size_t, TUNABLE_CALLBACK (set_mxfast));
#else
  if (__glibc_likely (_environ != NULL))
    {
      char **runp = _environ;
      char *envline;
      //依据环境变量内容，调用mallopt来设置一些可调参数
      while (__builtin_expect ((envline = next_env_entry (&runp)) != NULL,
                               0))
        {
          size_t len = strcspn (envline, "=");

          if (envline[len] != '=')
            /* This is a "MALLOC_" variable at the end of the string
               without a '=' character.  Ignore it since otherwise we
               will access invalid memory below.  */
            continue;

          switch (len)
            {
            case 8:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "TOP_PAD_", 8) == 0)
                    __libc_mallopt (M_TOP_PAD, atoi (&envline[9]));
                  else if (memcmp (envline, "PERTURB_", 8) == 0)
                    __libc_mallopt (M_PERTURB, atoi (&envline[9]));
                }
              break;
            case 9:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "MMAP_MAX_", 9) == 0)
                    __libc_mallopt (M_MMAP_MAX, atoi (&envline[10]));
                  else if (memcmp (envline, "ARENA_MAX", 9) == 0)
                    __libc_mallopt (M_ARENA_MAX, atoi (&envline[10]));
                }
              break;
            case 10:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "ARENA_TEST", 10) == 0)
                    __libc_mallopt (M_ARENA_TEST, atoi (&envline[11]));
                }
              break;
            case 15:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "TRIM_THRESHOLD_", 15) == 0)
                    __libc_mallopt (M_TRIM_THRESHOLD, atoi (&envline[16]));
                  else if (memcmp (envline, "MMAP_THRESHOLD_", 15) == 0)
                    __libc_mallopt (M_MMAP_THRESHOLD, atoi (&envline[16]));
                }
              break;
            default:
              break;
            }
        }
    }
#endif
}

/* Managing heaps and arenas (for concurrent threads) */

#if MALLOC_DEBUG > 1

/* Print the complete contents of a single heap to stderr. */

static void
dump_heap (heap_info *heap)
{
  char *ptr;
  mchunkptr p;

  fprintf (stderr, "Heap %p, size %10lx:\n", heap, (long) heap->size);
  ptr = (heap->ar_ptr != (mstate) (heap + 1)) ?
        (char *) (heap + 1) : (char *) (heap + 1) + sizeof (struct malloc_state);
  p = (mchunkptr) (((unsigned long) ptr + MALLOC_ALIGN_MASK) &
                   ~MALLOC_ALIGN_MASK);
  for (;; )
    {
      fprintf (stderr, "chunk %p size %10lx", p, (long) chunksize_nomask(p));
      if (p == top (heap->ar_ptr))
        {
          fprintf (stderr, " (top)\n");
          break;
        }
      else if (chunksize_nomask(p) == (0 | PREV_INUSE))
        {
          fprintf (stderr, " (fence)\n");
          break;
        }
      fprintf (stderr, "\n");
      p = next_chunk (p);
    }
}
#endif /* MALLOC_DEBUG > 1 */

/* If consecutive mmap (0, HEAP_MAX_SIZE << 1, ...) calls return decreasing
   addresses as opposed to increasing, new_heap would badly fragment the
   address space.  In that case remember the second HEAP_MAX_SIZE part
   aligned to HEAP_MAX_SIZE from last mmap (0, HEAP_MAX_SIZE << 1, ...)
   call (if it is already aligned) and try to reuse it next time.  We need
   no locking for it, as kernel ensures the atomicity for us - worst case
   we'll call mmap (addr, HEAP_MAX_SIZE, ...) for some value of addr in
   multiple threads, but only one will succeed.  */
static char *aligned_heap_area;

/* Create a new heap.  size is automatically rounded up to a multiple
   of the page size. */
//size既包含申请大小，还包含了heap的元数据，top_pad作用是在顶部多预申请一些内存
static heap_info *
new_heap (size_t size, size_t top_pad)
{
  size_t pagesize = GLRO (dl_pagesize);
  char *p1, *p2;
  unsigned long ul;
  heap_info *h;

  if (size + top_pad < HEAP_MIN_SIZE)//32K
    size = HEAP_MIN_SIZE;
  else if (size + top_pad <= HEAP_MAX_SIZE)//32:1M   64:32\64M 通常是64M
    size += top_pad;
  else if (size > HEAP_MAX_SIZE)//超过允许值，直接返回NULL
    return 0;
  else//多预申请的内存不满足要求，size满足要求，直接申请最大值
    size = HEAP_MAX_SIZE;
  size = ALIGN_UP (size, pagesize);//对size进行页对齐

  /* A memory region aligned to a multiple of HEAP_MAX_SIZE is needed.
     No swap space needs to be reserved for the following large
     mapping (on Linux, this is the case for all non-writable mappings
     anyway). */
  p2 = MAP_FAILED;
  if (aligned_heap_area)//这个变量主要用于减少虚拟地址空间碎片，表明偏向于两个连续的HEAP_MAX_SIZE挨着
    {
      //将aligned_heap_area作为hint，申请虚拟地址空间;
      //__mmap((addr), (size), (prot), (flags)|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0) 
      //MAP_ANONYMOUS：The mapping is not backed by any file; its contents are initialized to zero. 匿名映射会被初始化为0
      p2 = (char *) MMAP (aligned_heap_area, HEAP_MAX_SIZE, PROT_NONE,
                          MAP_NORESERVE);
      aligned_heap_area = NULL;
      if (p2 != MAP_FAILED && ((unsigned long) p2 & (HEAP_MAX_SIZE - 1)))//p2如果没有HEAP_MAX_SIZE对齐，则放弃这次映射
        {
          __munmap (p2, HEAP_MAX_SIZE);
          p2 = MAP_FAILED;
        }
    }
  if (p2 == MAP_FAILED)
    {
      //有内核随机分配，之后进行HEAP_MAX_SIZE对齐，为此将首尾多余的虚拟地址空间进行unmap      
      p1 = (char *) MMAP (0, HEAP_MAX_SIZE << 1, PROT_NONE, MAP_NORESERVE);
      if (p1 != MAP_FAILED)
        {
          p2 = (char *) (((unsigned long) p1 + (HEAP_MAX_SIZE - 1))
                         & ~(HEAP_MAX_SIZE - 1));//heap区域必定HEAP_MAX_SIZE
          ul = p2 - p1;
          if (ul)
            __munmap (p1, ul);
          else
            aligned_heap_area = p2 + HEAP_MAX_SIZE;//紧挨着的这个p2的下一个HEAP_MAX_SIZE地址用于下次尝试分配
          __munmap (p2 + HEAP_MAX_SIZE, HEAP_MAX_SIZE - ul);
        }
      else
        {
          /* Try to take the chance that an allocation of only HEAP_MAX_SIZE
             is already aligned. */
          p2 = (char *) MMAP (0, HEAP_MAX_SIZE, PROT_NONE, MAP_NORESERVE);
          if (p2 == MAP_FAILED)
            return 0;

          if ((unsigned long) p2 & (HEAP_MAX_SIZE - 1))
            {
              __munmap (p2, HEAP_MAX_SIZE);
              return 0;
            }
        }
    }
    //mprotect改变指定地址空间范围内的权限，如果有必要的话，一个VMA 可能因此分裂成多个VMA ，不同VMA 设置不同权限
    //虽然申请了HEAP_MAX_SIZE的空间，但是只有size范围内的heap允许读写，其它部分无法使用
  if (__mprotect (p2, size, mtag_mmap_flags | PROT_READ | PROT_WRITE) != 0)
    {
      __munmap (p2, HEAP_MAX_SIZE);
      return 0;
    }
  h = (heap_info *) p2;
  h->size = size;//从这来看,size/mprotect_size都是真正最终可用的内存区域,包含元数据
  h->mprotect_size = size;
  LIBC_PROBE (memory_heap_new, 2, h, h->size);
  return h;
}

/* Grow a heap.  size is automatically rounded up to a
   multiple of the page size. */
//没有mmap新的region，只是将之前不可读写的区域变成可读写，没有mmap新的region
//如果增长会超过HEAP_MAX_SIZE，则放弃增长返回-1；通常增长发生在topchunk空间不够使用
static int
grow_heap (heap_info *h, long diff)
{
  size_t pagesize = GLRO (dl_pagesize);
  long new_size;

  diff = ALIGN_UP (diff, pagesize);//diff是还需的内存大小，这里直接按页向上对齐
  new_size = (long) h->size + diff;//即使之前存在多个heap，h->size只是这个heap的szie
  if ((unsigned long) new_size > (unsigned long) HEAP_MAX_SIZE)
    return -1;

  if ((unsigned long) new_size > h->mprotect_size)
    {
      if (__mprotect ((char *) h + h->mprotect_size,
                      (unsigned long) new_size - h->mprotect_size,
                      mtag_mmap_flags | PROT_READ | PROT_WRITE) != 0)
        return -2;

      h->mprotect_size = new_size;
    }

  h->size = new_size;
  LIBC_PROBE (memory_heap_more, 2, h, h->size);
  return 0;
}

/* Shrink a heap.  */

static int
shrink_heap (heap_info *h, long diff)//diff为预期的缩减字节
{
  long new_size;

  new_size = (long) h->size - diff;//收缩后大小
  if (new_size < (long) sizeof (*h))//收缩后的剩余大小不能小于heap结构的大小
    return -1;

  /* Try to re-map the extra heap space freshly to save memory, and make it
     inaccessible.  See malloc-sysdep.h to know when this is true.  */
  if (__glibc_unlikely (check_may_shrink_heap ()))//unlikely
    {//这里的操作如同mprotect，对应的vma会进行分裂，区域存在，但是权限为---，没有任何read/write/exec权限
      if ((char *) MMAP ((char *) h + new_size, diff, PROT_NONE,
                         MAP_FIXED) == (char *) MAP_FAILED)
        return -2;

      h->mprotect_size = new_size;//设置可读可写的size范围
    }//likely
  else/* madvise is a stub（桩） on Hurd, so don't bother calling it.  *///像是主要用在gnu操作系统hurd中
    __madvise ((char *) h + new_size, diff, MADV_DONTNEED);//具体的实现好像是直接设置errno=ENOSYS即函数未实现，然后直接返回-1，相当于啥也没做
  /*fprintf(stderr, "shrink %p %08lx\n", h, new_size);*/
  //只改变了size，如果上面if走的likely分支，那么heap中的mprotect_size就没有变化，对应的vma实际也没有变化（没有释放虚拟地址空间）,
  //shrink的效果只是让chunk的分配释放存在校验,但是其它的页是可以写的，除非走了unlikey分支
  h->size = new_size;
  LIBC_PROBE (memory_heap_less, 2, h, h->size);
  return 0;
}

/* Delete a heap. */

#define delete_heap(heap) \
  do {									      \
      if ((char *) (heap) + HEAP_MAX_SIZE == aligned_heap_area)		      \
        aligned_heap_area = NULL;					      \ //将之前的hint取消（这个变量之前用于减少2个heap以内的虚拟地址空间碎片）
      __munmap ((char *) (heap), HEAP_MAX_SIZE);			      \//unmap
    } while (0)

static int
heap_trim (heap_info *heap, size_t pad)
{
  mstate ar_ptr = heap->ar_ptr;
  unsigned long pagesz = GLRO (dl_pagesize);
  mchunkptr top_chunk = top (ar_ptr), p;
  heap_info *prev_heap;
  long new_size, top_size, top_area, extra, prev_size, misalign;
  //从后往前，依次判断整个heap能否delete，能删除就删，遇到第一个不能删除就break
  /* Can this heap go away completely? */
  while (top_chunk == chunk_at_offset (heap, sizeof (*heap)))//为真说明topchunk为唯一的chunk,并且不是含有arena的heap,必然有prev_heap
    {
      prev_heap = heap->prev;//前一个heap
      prev_size = prev_heap->size - (MINSIZE - 2 * SIZE_SZ);//从数值上看 （MINSIZE-2*SIZE_SZ）=2个指针占内存大小：32/8byte  64/16byte 64/24byte
      p = chunk_at_offset (prev_heap, prev_size);//得到prev_heap+prev_size的地址
      /* fencepost must be properly aligned.  */
      misalign = ((long) p) & MALLOC_ALIGN_MASK;//misalign: 32:8byte  64/16:0byte  64/24:8byte
      //从数据上来看，像是找到最后一个大小为MINSIZE（或者能容纳prev_size和size的大小）且地址是MALLOC_ALIGN_MASK对齐的chunk（必须有头，但可以没有数据区）;
      //之所以这么操作，像是因为未假定prev_heap->size 的对应地址对齐性；猜测这样做是因为只有MALLOC_ALIGN_MASK对齐的chunk才能通过内部的一些chunk check
      p = chunk_at_offset (prev_heap, prev_size - misalign);//从代码来看，这最后一个chunk(必须有头，但可以无数据区)被视为一个fencepost(栅栏柱)，且其对应的PREV_INUSE被设置
      assert (chunksize_nomask (p) == (0 | PREV_INUSE)); /* must be fencepost */ /
      p = prev_chunk (p);//fencepost的前一个chunk
      new_size = chunksize (p) + (MINSIZE - 2 * SIZE_SZ) + misalign;//将fencepost合并到p对应的chunk（真正意义上这个heap中的最后一个chunk）的大小
      assert (new_size > 0 && new_size < (long) (2 * MINSIZE));//校验new_size?？？暂时不明白为什么是这样的校验
      if (!prev_inuse (p))//p的prev_inuse是free,就考虑合并末尾,计算newsize
        new_size += prev_size (p);
      assert (new_size > 0 && new_size < HEAP_MAX_SIZE);//new_size校验
      if (new_size + (HEAP_MAX_SIZE - prev_heap->size) < pad + MINSIZE + pagesz)//如果释放的空间小于1页多点，直接break，放弃unmap heap
        break;
      ar_ptr->system_mem -= heap->size;//减少记录的从系统分配的内存量
      LIBC_PROBE (memory_heap_free, 2, heap, heap->size);
      delete_heap (heap);//unmap heap
      heap = prev_heap;//prev_heap设置为heap
      if (!prev_inuse (p)) /* consolidate backward */ //p的prev_inuse是free,就要进行合并合并末尾
        {
          p = prev_chunk (p);//将free的chunk从所属链表中移出
          unlink_chunk (ar_ptr, p);
        }
      assert (((unsigned long) ((char *) p + new_size) & (pagesz - 1)) == 0);//heap尾地址检测
      assert (((char *) p + new_size) == ((char *) heap + heap->size));//heap size检测
      top (ar_ptr) = top_chunk = p;//将p设置为top chunk
      set_head (top_chunk, new_size | PREV_INUSE);//设置PREV_INUSE标识
      /*check_chunk(ar_ptr, top_chunk);*/
    }

  /* Uses similar logic for per-thread arenas as the main arena with systrim
     and _int_free by preserving the top pad and rounding down to the nearest
     page.  */
  //接下来的处理就类似main arena中topchunk的缩减过程了
  top_size = chunksize (top_chunk);
  if ((unsigned long)(top_size) <
      (unsigned long)(mp_.trim_threshold))//没有到收缩的阈值，直接返回
    return 0;

  top_area = top_size - MINSIZE - 1;
  if (top_area < 0 || (size_t) top_area <= pad)//空间太小直接返回
    return 0;

  /* Release in pagesize units and round down to the nearest page.  */
  extra = ALIGN_DOWN(top_area - pad, pagesz);//对其后，可以释放的字节数（页对齐了，并且剩余的大小不算pad基本在1页的规模程度，不会很大）
  if (extra == 0)
    return 0;

  /* Try to shrink. */
  if (shrink_heap (heap, extra) != 0)//尝试shrink收缩???
    return 0;
  //通过shrink heap的代码可以推测这个system_mem字段用在chunk检测上
  //但是同一个heap已经申请的内存是不会释放的（虚拟地址空间不会释放，可能会分类一个无权限的vma，
  //也可能仅仅是改变heap和arena上关于记录可用字节的值，在chunk申请释放时进行检测，但是未使用的页实际是可以写入的（若未分裂））
  ar_ptr->system_mem -= extra;//成功的话减小从系统申请的内存的记录量

  /* Success. Adjust top accordingly. */
  set_head (top_chunk, (top_size - extra) | PREV_INUSE);//设置收缩后的top chunk的size
  /*check_chunk(ar_ptr, top_chunk);*/
  return 1;
}

/* Create a new arena with initial size "size".  */

#if IS_IN (libc)
/* If REPLACED_ARENA is not NULL, detach it from this thread.  Must be
   called while free_list_lock is held.  */
static void
detach_arena (mstate replaced_arena)
{
  if (replaced_arena != NULL)
    {
      assert (replaced_arena->attached_threads > 0);
      /* The current implementation only detaches from main_arena in
	 case of allocation failure.  This means that it is likely not
	 beneficial to put the arena on free_list even if the
	 reference count reaches zero.  */
      --replaced_arena->attached_threads;
    }
}
//这里新建的arena都是非main_arena,申请成功后会加入next链表；
//size是一个hint告诉新建的arena的空间要能容下size
//但不是绝对，如果一个heap装不下，那么会新建一个最小的能容下元数据并满足相关对齐要求的arena及其附属的heap
static mstate
_int_new_arena (size_t size)
{
  mstate a;
  heap_info *h;
  char *ptr;
  unsigned long misalign;
  //sizeof(*h)等同于sizeof(heap_info)获取heap_info结构的大小
  //Create a new heap.这里很明显将mmap出来 的start地址作为heap_info的收地址
  //new heap区域被mmap匿名映射出来时区域中的值都初始化为0，因而arena中fastbin等都为0，其他值需要后续进一步设置
  h = new_heap (size + (sizeof (*h) + sizeof (*a) + MALLOC_ALIGNMENT),
                mp_.top_pad);
  if (!h)
    {//申请大小可能太大了，不能再一个heap放下，那么就考虑让后面_int_malloc来处理，先申请一个不包含申请内存的最小的heap
      /* Maybe size is too large to fit in a single heap.  So, just try
         to create a minimally-sized arena and let _int_malloc() attempt
         to deal with the large request via mmap_chunk().  */
      h = new_heap (sizeof (*h) + sizeof (*a) + MALLOC_ALIGNMENT, mp_.top_pad);
      if (!h)
        return 0;
    }
    //将arena设置为紧挨着heap_info位置的地方
  a = h->ar_ptr = (mstate) (h + 1);
  malloc_init_state (a);//初始化arena
  a->attached_threads = 1;
  /*a->next = NULL;*/
  a->system_mem = a->max_system_mem = h->size;/* mmap且读写区域的大小，h->size页对齐  */

  /* Set up the top chunk, with proper alignment. */
  ptr = (char *) (a + 1);
  misalign = (unsigned long) chunk2mem (ptr) & MALLOC_ALIGN_MASK;
  if (misalign > 0)
    ptr += MALLOC_ALIGNMENT - misalign;//修正ptr，让ptr对齐MALLOC_ALIGNMENT
  top (a) = (mchunkptr) ptr;//设置arena的top,top尾部页对齐
  set_head (top (a), (((char *) h + h->size) - ptr) | PREV_INUSE);//初始化top_chunk的mchunk_size并且设置PREV_INUSE

  LIBC_PROBE (memory_arena_new, 2, a, size);
  mstate replaced_arena = thread_arena;//从这开始后面的操作基本上就是将新创建的arena加入next链表
  thread_arena = a;
  __libc_lock_init (a->mutex);

  __libc_lock_lock (list_lock);

  /* Add the new arena to the global list.  */
  a->next = main_arena.next;
  /* FIXME: The barrier is an attempt to synchronize with read access
     in reused_arena, which does not acquire list_lock while
     traversing the list.  */
  atomic_write_barrier ();
  main_arena.next = a;

  __libc_lock_unlock (list_lock);

  __libc_lock_lock (free_list_lock);
  detach_arena (replaced_arena);
  __libc_lock_unlock (free_list_lock);

  /* Lock this arena.  NB: Another thread may have been attached to
     this arena because the arena is now accessible from the
     main_arena.next list and could have been picked by reused_arena.
     This can only happen for the last arena created (before the arena
     limit is reached).  At this point, some arena has to be attached
     to two threads.  We could acquire the arena lock before list_lock
     to make it less likely that reused_arena picks this new arena,
     but this could result in a deadlock with
     __malloc_fork_lock_parent.  */

  __libc_lock_lock (a->mutex);

  return a;
}


/* Remove an arena from free_list.  */
//默认有一个arena free list，可以从里面获取一个free arena，并从free list列表中移除;
//在多线程环境中某个父线程fork后，父子线程刚开始时共享内存空间，但只有被fork的线程的arena会被使用，其它的在子线程中不会被使用了，所以将他们放入了freelist
//类似的还有线程栈，只有当前线程栈还会被使用，其它的线程栈就不再会使用了，这些线程栈的空间也要被回收
//这些操作发生在glibc的fork方法（不是系统调用）
static mstate
get_free_list (void)
{
  mstate replaced_arena = thread_arena;
  mstate result = free_list;
  if (result != NULL)
    {
      __libc_lock_lock (free_list_lock);
      result = free_list;
      if (result != NULL)
	{
	  free_list = result->next_free;

	  /* The arena will be attached to this thread.  */
	  assert (result->attached_threads == 0);
	  result->attached_threads = 1;

	  detach_arena (replaced_arena);//使得thread对应的arena的attached_threads减1
	}
      __libc_lock_unlock (free_list_lock);

      if (result != NULL)
        {
          //aid in debugging and monitoring internal behavior
          LIBC_PROBE (memory_arena_reuse_free_list, 1, result);
          __libc_lock_lock (result->mutex);
	  thread_arena = result;
        }
    }

  return result;
}

/* Remove the arena from the free list (if it is present).
   free_list_lock must have been acquired by the caller.  */
static void
remove_from_free_list (mstate arena)
{
  mstate *previous = &free_list;//free_list是mstate中next_free属性构成的链表
  for (mstate p = free_list; p != NULL; p = p->next_free)
    {
      assert (p->attached_threads == 0);//这个断言说明free_list中arena没有关联任何线程
      if (p == arena)
	{
	  /* Remove the requested arena from the list.  */
	  *previous = p->next_free;
	  break;
	}
      else
	previous = &p->next_free;
    }
}

/* Lock and return an arena that can be reused for memory allocation.
   Avoid AVOID_ARENA as we have already failed to allocate memory in
   it and it is currently locked.  */
static mstate
reused_arena (mstate avoid_arena)
{
  mstate result;
  /* FIXME: Access to next_to_use suffers from data races.  */
  static mstate next_to_use;//局部静态变量，每次进入时都是上一次进入时的值
  if (next_to_use == NULL)
    next_to_use = &main_arena;//第一次的话，就从Main_arean开始

  /* Iterate over all arenas (including those linked from
     free_list).  */
  result = next_to_use;
  do
    {
      if (!__libc_lock_trylock (result->mutex))//获取成功，返回false;获取失败返回ture
        goto out;

      /* FIXME: This is a data race, see _int_new_arena.  */
      result = result->next;//下一个
    }
  while (result != next_to_use);//当竞争的时候，条件为真，再一次循环

  /* Avoid AVOID_ARENA as we have already failed to allocate memory
     in that arena and it is currently locked.   */
  if (result == avoid_arena)//如果是avoid_arena，选择下一个
    result = result->next;

  /* No arena available without contention.  Wait for the next in line.  */
  LIBC_PROBE (memory_arena_reuse_wait, 3, &result->mutex, result, avoid_arena);
  __libc_lock_lock (result->mutex);//等待获取锁

out:
  /* Attach the arena to the current thread.  */
  {
    /* Update the arena thread attachment counters.   */
    mstate replaced_arena = thread_arena;
    __libc_lock_lock (free_list_lock);
    detach_arena (replaced_arena);//原线程arena拥有的线程计数--

    /* We may have picked up an arena on the free list.  We need to
       preserve the invariant that no arena on the free list has a
       positive attached_threads counter (otherwise,
       arena_thread_freeres cannot use the counter to determine if the
       arena needs to be put on the free list).  We unconditionally
       remove the selected arena from the free list.  The caller of
       reused_arena checked the free list and observed it to be empty,
       so the list is very short.  */
    remove_from_free_list (result);//Remove the arena from the free list (if it is present).

    ++result->attached_threads;

    __libc_lock_unlock (free_list_lock);
  }

  LIBC_PROBE (memory_arena_reuse, 2, result, avoid_arena);
  thread_arena = result;//线程arena设置为新的arena
  next_to_use = result->next;//修改next_to_use

  return result;
}

static mstate
arena_get2 (size_t size, mstate avoid_arena)
{
  mstate a;

  static size_t narenas_limit;

  a = get_free_list ();
  if (a == NULL)
    {
      /* Nothing immediately available, so generate a new arena.  */
      if (narenas_limit == 0)
        {
          // There is only one instance of the malloc parameters.  static struct malloc_par mp_  其中的一些参数收到mallopt影响
          if (mp_.arena_max != 0)
            narenas_limit = mp_.arena_max;
          else if (narenas > mp_.arena_test)
            {
              int n = __get_nprocs ();//获取核心数

              if (n >= 1)
                narenas_limit = NARENAS_FROM_NCORES (n);//32：n*2   64:n*8
              else
                /* We have no information about the system.  Assume two
                   cores.  */
                narenas_limit = NARENAS_FROM_NCORES (2);
            }
        }
    repeat:;
      size_t n = narenas;
      /* NB: the following depends on the fact that (size_t)0 - 1 is a
         very large number and that the underflow is OK.  If arena_max
         is set the value of arena_test is irrelevant.  If arena_test
         is set but narenas is not yet larger or equal to arena_test
         narenas_limit is 0.  There is no possibility for narenas to
         be too big for the test to always fail since there is not
         enough address space to create that many arenas.  */
      if (__glibc_unlikely (n <= narenas_limit - 1))
        {
          if (catomic_compare_and_exchange_bool_acq (&narenas, n + 1, n))//CAS 如果计数成功，则返回false，进入_int_new_arena
            goto repeat;
          a = _int_new_arena (size);//这里新建的arena都是非main_arena,申请成功后会加入next链表
	  if (__glibc_unlikely (a == NULL))
            catomic_decrement (&narenas);//申请失败，则退回计数
        }
      else
      /* Lock and return an arena that can be reused for memory allocation.
         Avoid AVOID_ARENA as we have already failed to allocate memory in  it and it is currently locked.  */
        a = reused_arena (avoid_arena);//简单理解就是遍历arena,获取第一个next能使用的arena，如果遇到的第一个是avoid_arena，则返回avoid_arena.next
    }
  return a;
}

/* If we don't have the main arena, then maybe the failure is due to running
   out of mmapped areas, so we can try allocating on the main arena.
   Otherwise, it is likely that sbrk() has failed and there is still a chance
   to mmap(), so try one of the other arenas.  */
   
static mstate
arena_get_retry (mstate ar_ptr, size_t bytes)
{
  LIBC_PROBE (memory_arena_retry, 2, bytes, ar_ptr);
  if (ar_ptr != &main_arena)
    {
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = &main_arena;
      __libc_lock_lock (ar_ptr->mutex);
    }
  else
    {
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = arena_get2 (bytes, ar_ptr);
    }

  return ar_ptr;
}
#endif

void
__malloc_arena_thread_freeres (void)
{
  /* Shut down the thread cache first.  This could deallocate data for
     the thread arena, so do this before we put the arena on the free
     list.  */
  tcache_thread_shutdown ();

  mstate a = thread_arena;
  thread_arena = NULL;

  if (a != NULL)
    {
      __libc_lock_lock (free_list_lock);
      /* If this was the last attached thread for this arena, put the
	 arena on the free list.  */
      assert (a->attached_threads > 0);
      if (--a->attached_threads == 0)
	{
	  a->next_free = free_list;
	  free_list = a;
	}
      __libc_lock_unlock (free_list_lock);
    }
}

/*
 * Local variables:
 * c-basic-offset: 2
 * End:
 */
