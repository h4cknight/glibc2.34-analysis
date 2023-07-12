/* Malloc implementation for multiple threads without lock contention.
   Copyright (C) 1996-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Wolfram Gloger <wg@malloc.de>
   and Doug Lea <dl@cs.oswego.edu>, 2001.

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

/*
  This is a version (aka ptmalloc2) of malloc/free/realloc written by
  Doug Lea and adapted to multiple threads/arenas by Wolfram Gloger.

  There have been substantial changes made after the integration into
  glibc in all parts of the code.  Do not look for much commonality
  with the ptmalloc2 version.

* Version ptmalloc2-20011215
  based on:
  VERSION 2.7.0 Sun Mar 11 14:14:06 2001  Doug Lea  (dl at gee)

* Quickstart

  In order to compile this implementation, a Makefile is provided with
  the ptmalloc2 distribution, which has pre-defined targets for some
  popular systems (e.g. "make posix" for Posix threads).  All that is
  typically required with regard to compiler flags is the selection of
  the thread package via defining one out of USE_PTHREADS, USE_THR or
  USE_SPROC.  Check the thread-m.h file for what effects this has.
  Many/most systems will additionally require USE_TSD_DATA_HACK to be
  defined, so this is the default for "make posix".

* Why use this malloc?

  This is not the fastest, most space-conserving, most portable, or
  most tunable malloc ever written. However it is among the fastest
  while also being among the most space-conserving, portable and tunable.
  Consistent balance across these factors results in a good general-purpose
  allocator for malloc-intensive programs.

    The main properties of the algorithms are:
  * For large (>= 512 bytes) requests, it is a pure best-fit allocator,
    with ties normally decided via FIFO (i.e. least recently used).
  * For small (<= 64 bytes by default) requests, it is a caching
    allocator, that maintains pools of quickly recycled chunks.
  * In between, and for combinations of large and small requests, it does
    the best it can trying to meet both goals at once.
  * For very large requests (>= 128KB by default), it relies on system
    memory mapping facilities, if supported.

  For a longer but slightly out of date high-level description, see
     http://gee.cs.oswego.edu/dl/html/malloc.html

  You may already by default be using a C library containing a malloc
  that is  based on some version of this malloc (for example in
  linux). You might still want to use the one in this file in order to
  customize settings or to avoid overheads associated with library
  versions.

* Contents, described in more detail in "description of public routines" below.

  Standard (ANSI/SVID/...)  functions:
    malloc(size_t n);
    calloc(size_t n_elements, size_t element_size);
    free(void* p);
    realloc(void* p, size_t n);
    memalign(size_t alignment, size_t n);
    valloc(size_t n);
    mallinfo()
    mallopt(int parameter_number, int parameter_value)

  Additional functions:
    independent_calloc(size_t n_elements, size_t size, void* chunks[]);
    independent_comalloc(size_t n_elements, size_t sizes[], void* chunks[]);
    pvalloc(size_t n);
    malloc_trim(size_t pad);
    malloc_usable_size(void* p);
    malloc_stats();

* Vital statistics:

  Supported pointer representation:       4 or 8 bytes
  Supported size_t  representation:       4 or 8 bytes
       Note that size_t is allowed to be 4 bytes even if pointers are 8.
       You can adjust this by defining INTERNAL_SIZE_T

  Alignment:                              2 * sizeof(size_t) (default)
       (i.e., 8 byte alignment with 4byte size_t). This suffices for
       nearly all current machines and C compilers. However, you can
       define MALLOC_ALIGNMENT to be wider than this if necessary.

  Minimum overhead per allocated chunk:   4 or 8 bytes
       Each malloced chunk has a hidden word of overhead holding size
       and status information.

  Minimum allocated size: 4-byte ptrs:  16 bytes    (including 4 overhead)
			  8-byte ptrs:  24/32 bytes (including, 4/8 overhead)

       When a chunk is freed, 12 (for 4byte ptrs) or 20 (for 8 byte
       ptrs but 4 byte size) or 24 (for 8/8) additional bytes are
       needed; 4 (8) for a trailing size field and 8 (16) bytes for
       free list pointers. Thus, the minimum allocatable size is
       16/24/32 bytes.

       Even a request for zero bytes (i.e., malloc(0)) returns a
       pointer to something of the minimum allocatable size.

       The maximum overhead wastage (i.e., number of extra bytes
       allocated than were requested in malloc) is less than or equal
       to the minimum size, except for requests >= mmap_threshold that
       are serviced via mmap(), where the worst case wastage is 2 *
       sizeof(size_t) bytes plus the remainder from a system page (the
       minimal mmap unit); typically 4096 or 8192 bytes.

  Maximum allocated size:  4-byte size_t: 2^32 minus about two pages
			   8-byte size_t: 2^64 minus about two pages

       It is assumed that (possibly signed) size_t values suffice to
       represent chunk sizes. `Possibly signed' is due to the fact
       that `size_t' may be defined on a system as either a signed or
       an unsigned type. The ISO C standard says that it must be
       unsigned, but a few systems are known not to adhere to this.
       Additionally, even when size_t is unsigned, sbrk (which is by
       default used to obtain memory from system) accepts signed
       arguments, and may not be able to handle size_t-wide arguments
       with negative sign bit.  Generally, values that would
       appear as negative after accounting for overhead and alignment
       are supported only via mmap(), which does not have this
       limitation.

       Requests for sizes outside the allowed range will perform an optional
       failure action and then return null. (Requests may also
       also fail because a system is out of memory.)

  Thread-safety: thread-safe

  Compliance: I believe it is compliant with the 1997 Single Unix Specification
       Also SVID/XPG, ANSI C, and probably others as well.

* Synopsis of compile-time options:

    People have reported using previous versions of this malloc on all
    versions of Unix, sometimes by tweaking some of the defines
    below. It has been tested most extensively on Solaris and Linux.
    People also report using it in stand-alone embedded systems.

    The implementation is in straight, hand-tuned ANSI C.  It is not
    at all modular. (Sorry!)  It uses a lot of macros.  To be at all
    usable, this code should be compiled using an optimizing compiler
    (for example gcc -O3) that can simplify expressions and control
    paths. (FAQ: some macros import variables as arguments rather than
    declare locals because people reported that some debuggers
    otherwise get confused.)

    OPTION                     DEFAULT VALUE

    Compilation Environment options:

    HAVE_MREMAP                0

    Changing default word sizes:

    INTERNAL_SIZE_T            size_t

    Configuration and functionality options:

    USE_PUBLIC_MALLOC_WRAPPERS NOT defined
    USE_MALLOC_LOCK            NOT defined
    MALLOC_DEBUG               NOT defined
    REALLOC_ZERO_BYTES_FREES   1
    TRIM_FASTBINS              0

    Options for customizing MORECORE:

    MORECORE                   sbrk
    MORECORE_FAILURE           -1
    MORECORE_CONTIGUOUS        1
    MORECORE_CANNOT_TRIM       NOT defined
    MORECORE_CLEARS            1
    MMAP_AS_MORECORE_SIZE      (1024 * 1024)

    Tuning options that are also dynamically changeable via mallopt:

    DEFAULT_MXFAST             64 (for 32bit), 128 (for 64bit)
    DEFAULT_TRIM_THRESHOLD     128 * 1024
    DEFAULT_TOP_PAD            0
    DEFAULT_MMAP_THRESHOLD     128 * 1024
    DEFAULT_MMAP_MAX           65536

    There are several other #defined constants and macros that you
    probably don't want to touch unless you are extending or adapting malloc.  */

/*
  void* is the pointer type that malloc should say it returns
*/

#ifndef void
#define void      void
#endif /*void*/

#include <stddef.h>   /* for size_t */
#include <stdlib.h>   /* for getenv(), abort() */
#include <unistd.h>   /* for __libc_enable_secure */

#include <atomic.h>
#include <_itoa.h>
#include <bits/wordsize.h>
#include <sys/sysinfo.h>

#include <ldsodefs.h>

#include <unistd.h>
#include <stdio.h>    /* needed for malloc_stats */
#include <errno.h>
#include <assert.h>

#include <shlib-compat.h>

/* For uintptr_t.  */
#include <stdint.h>

/* For va_arg, va_start, va_end.  */
#include <stdarg.h>

/* For MIN, MAX, powerof2.  */
#include <sys/param.h>

/* For ALIGN_UP et. al.  */
#include <libc-pointer-arith.h>

/* For DIAG_PUSH/POP_NEEDS_COMMENT et al.  */
#include <libc-diag.h>

/* For memory tagging.  */
#include <libc-mtag.h>

#include <malloc/malloc-internal.h>

/* For SINGLE_THREAD_P.  */
#include <sysdep-cancel.h>

#include <libc-internal.h>

/* For tcache double-free check.  */
#include <random-bits.h>
#include <sys/random.h>

/*
  Debugging:

  Because freed chunks may be overwritten with bookkeeping fields, this
  malloc will often die when freed memory is overwritten by user
  programs.  This can be very effective (albeit in an annoying way)
  in helping track down dangling pointers.

  If you compile with -DMALLOC_DEBUG, a number of assertion checks are
  enabled that will catch more memory errors. You probably won't be
  able to make much sense of the actual assertion errors, but they
  should help you locate incorrectly overwritten memory.  The checking
  is fairly extensive, and will slow down execution
  noticeably. Calling malloc_stats or mallinfo with MALLOC_DEBUG set
  will attempt to check every non-mmapped allocated and free chunk in
  the course of computing the summmaries. (By nature, mmapped regions
  cannot be checked very much automatically.)

  Setting MALLOC_DEBUG may also be helpful if you are trying to modify
  this code. The assertions in the check routines spell out in more
  detail the assumptions and invariants underlying the algorithms.

  Setting MALLOC_DEBUG does NOT provide an automated mechanism for
  checking that all accesses to malloced memory stay within their
  bounds. However, there are several add-ons and adaptations of this
  or other mallocs available that do this.
*/

#ifndef MALLOC_DEBUG
#define MALLOC_DEBUG 0
#endif

#if IS_IN (libc)
#ifndef NDEBUG
# define __assert_fail(assertion, file, line, function)			\
	 __malloc_assert(assertion, file, line, function)

extern const char *__progname;

static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}
#endif
#endif

#if USE_TCACHE
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS		64
# define MAX_TCACHE_SIZE	tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7

/* Maximum chunks in tcache bins for tunables.  This value must fit the range
   of tcache->counts[] entries, else they may overflow.  */
# define MAX_TCACHE_COUNT UINT16_MAX
#endif

/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
//a^b^a=b  异或自反定律,这里(&ptr)>>12获的是ptr变量所在的页地址
//用这个具有随机性的地址掩码真实地址ptr变量值，得到一个加密后的地址放入tcache链表
//这样，如果想单纯的劫持fastbin tcache的元数据指针就变得很困难
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr) 
/*
  The REALLOC_ZERO_BYTES_FREES macro controls the behavior of realloc (p, 0)
  when p is nonnull.  If the macro is nonzero, the realloc call returns NULL;
  otherwise, the call returns what malloc (0) would.  In either case,
  p is freed.  Glibc uses a nonzero REALLOC_ZERO_BYTES_FREES, which
  implements common historical practice.

  ISO C17 says the realloc call has implementation-defined behavior,
  and it might not even free p.
*/

#ifndef REALLOC_ZERO_BYTES_FREES
#define REALLOC_ZERO_BYTES_FREES 1
#endif

/*
  TRIM_FASTBINS controls whether free() of a very small chunk can
  immediately lead to trimming. Setting to true (1) can reduce memory
  footprint, but will almost always slow down programs that use a lot
  of small chunks.

  Define this only if you are willing to give up some speed to more
  aggressively reduce system-level memory footprint when releasing
  memory in programs that use many small chunks.  You can get
  essentially the same effect by setting MXFAST to 0, but this can
  lead to even greater slowdowns in programs using many small chunks.
  TRIM_FASTBINS is an in-between compile-time option, that disables
  only those chunks bordering topmost memory from being placed in
  fastbins.
*/

#ifndef TRIM_FASTBINS
#define TRIM_FASTBINS  0
#endif

/* Definition for getting more memory from the OS.  */
#include "morecore.c"

#define MORECORE         (*__glibc_morecore)
#define MORECORE_FAILURE 0

/* Memory tagging.  */

/* Some systems support the concept of tagging (sometimes known as
   coloring) memory locations on a fine grained basis.  Each memory
   location is given a color (normally allocated randomly) and
   pointers are also colored.  When the pointer is dereferenced, the
   pointer's color is checked against the memory's color and if they
   differ the access is faulted (sometimes lazily).

   We use this in glibc by maintaining a single color for the malloc
   data structures that are interleaved with the user data and then
   assigning separate colors for each block allocation handed out.  In
   this way simple buffer overruns will be rapidly detected.  When
   memory is freed, the memory is recolored back to the glibc default
   so that simple use-after-free errors can also be detected.

   If memory is reallocated the buffer is recolored even if the
   address remains the same.  This has a performance impact, but
   guarantees that the old pointer cannot mistakenly be reused (code
   that compares old against new will see a mismatch and will then
   need to behave as though realloc moved the data to a new location).

   Internal API for memory tagging support.

   The aim is to keep the code for memory tagging support as close to
   the normal APIs in glibc as possible, so that if tagging is not
   enabled in the library, or is disabled at runtime then standard
   operations can continue to be used.  Support macros are used to do
   this:

   void *tag_new_zero_region (void *ptr, size_t size)

   Allocates a new tag, colors the memory with that tag, zeros the
   memory and returns a pointer that is correctly colored for that
   location.  The non-tagging version will simply call memset with 0.

   void *tag_region (void *ptr, size_t size)

   Color the region of memory pointed to by PTR and size SIZE with
   the color of PTR.  Returns the original pointer.

   void *tag_new_usable (void *ptr)

   Allocate a new random color and use it to color the user region of
   a chunk; this may include data from the subsequent chunk's header
   if tagging is sufficiently fine grained.  Returns PTR suitably
   recolored for accessing the memory there.

   void *tag_at (void *ptr)

   Read the current color of the memory at the address pointed to by
   PTR (ignoring it's current color) and return PTR recolored to that
   color.  PTR must be valid address in all other respects.  When
   tagging is not enabled, it simply returns the original pointer.
*/

#ifdef USE_MTAG
static bool mtag_enabled = false;
static int mtag_mmap_flags = 0;
#else
# define mtag_enabled false
# define mtag_mmap_flags 0
#endif

static __always_inline void *
tag_region (void *ptr, size_t size)
{
  if (__glibc_unlikely (mtag_enabled))
    return __libc_mtag_tag_region (ptr, size);
  return ptr;
}

static __always_inline void *
tag_new_zero_region (void *ptr, size_t size)
{
  if (__glibc_unlikely (mtag_enabled))
    return __libc_mtag_tag_zero_region (__libc_mtag_new_tag (ptr), size);
  return memset (ptr, 0, size);
}

/* Defined later.  */
static void *
tag_new_usable (void *ptr);

static __always_inline void *
tag_at (void *ptr)
{
  if (__glibc_unlikely (mtag_enabled))
    return __libc_mtag_address_get_tag (ptr);
  return ptr;
}

#include <string.h>

/*
  MORECORE-related declarations. By default, rely on sbrk
*/


/*
  MORECORE is the name of the routine to call to obtain more memory
  from the system.  See below for general guidance on writing
  alternative MORECORE functions, as well as a version for WIN32 and a
  sample version for pre-OSX macos.
*/

#ifndef MORECORE
#define MORECORE sbrk
#endif

/*
  MORECORE_FAILURE is the value returned upon failure of MORECORE
  as well as mmap. Since it cannot be an otherwise valid memory address,
  and must reflect values of standard sys calls, you probably ought not
  try to redefine it.
*/

#ifndef MORECORE_FAILURE
#define MORECORE_FAILURE (-1)
#endif

/*
  If MORECORE_CONTIGUOUS is true, take advantage of fact that
  consecutive calls to MORECORE with positive arguments always return
  contiguous increasing addresses.  This is true of unix sbrk.  Even
  if not defined, when regions happen to be contiguous, malloc will
  permit allocations spanning regions obtained from different
  calls. But defining this when applicable enables some stronger
  consistency checks and space efficiencies.
*/

#ifndef MORECORE_CONTIGUOUS
#define MORECORE_CONTIGUOUS 1
#endif

/*
  Define MORECORE_CANNOT_TRIM if your version of MORECORE
  cannot release space back to the system when given negative
  arguments. This is generally necessary only if you are using
  a hand-crafted MORECORE function that cannot handle negative arguments.
*/

/* #define MORECORE_CANNOT_TRIM */

/*  MORECORE_CLEARS           (default 1)
     The degree to which the routine mapped to MORECORE zeroes out
     memory: never (0), only for newly allocated space (1) or always
     (2).  The distinction between (1) and (2) is necessary because on
     some systems, if the application first decrements and then
     increments the break value, the contents of the reallocated space
     are unspecified.
 */

#ifndef MORECORE_CLEARS
# define MORECORE_CLEARS 1
#endif


/*
   MMAP_AS_MORECORE_SIZE is the minimum mmap size argument to use if
   sbrk fails, and mmap is used as a backup.  The value must be a
   multiple of page size.  This backup strategy generally applies only
   when systems have "holes" in address space, so sbrk cannot perform
   contiguous expansion, but there is still space available on system.
   On systems for which this is known to be useful (i.e. most linux
   kernels), this occurs only when programs allocate huge amounts of
   memory.  Between this, and the fact that mmap regions tend to be
   limited, the size should be large, to avoid too many mmap calls and
   thus avoid running out of kernel resources.  */

#ifndef MMAP_AS_MORECORE_SIZE
#define MMAP_AS_MORECORE_SIZE (1024 * 1024)
#endif

/*
  Define HAVE_MREMAP to make realloc() use mremap() to re-allocate
  large blocks.
*/

#ifndef HAVE_MREMAP
#define HAVE_MREMAP 0
#endif

/*
  This version of malloc supports the standard SVID/XPG mallinfo
  routine that returns a struct containing usage properties and
  statistics. It should work on any SVID/XPG compliant system that has
  a /usr/include/malloc.h defining struct mallinfo. (If you'd like to
  install such a thing yourself, cut out the preliminary declarations
  as described above and below and save them in a malloc.h file. But
  there's no compelling reason to bother to do this.)

  The main declaration needed is the mallinfo struct that is returned
  (by-copy) by mallinfo().  The SVID/XPG malloinfo struct contains a
  bunch of fields that are not even meaningful in this version of
  malloc.  These fields are are instead filled by mallinfo() with
  other numbers that might be of interest.
*/


/* ---------- description of public routines ------------ */

#if IS_IN (libc)
/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.

  If n is zero, malloc returns a minimum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/
void*  __libc_malloc(size_t);
libc_hidden_proto (__libc_malloc)

/*
  free(void* p)
  Releases the chunk of memory pointed to by p, that had been previously
  allocated using malloc or a related routine such as realloc.
  It has no effect if p is null. It can have arbitrary (i.e., bad!)
  effects if p has already been freed.

  Unless disabled (using mallopt), freeing very large spaces will
  when possible, automatically trigger operations that give
  back unused memory to the system, thus reducing program footprint.
*/
void     __libc_free(void*);
libc_hidden_proto (__libc_free)

/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
void*  __libc_calloc(size_t, size_t);

/*
  realloc(void* p, size_t n)
  Returns a pointer to a chunk of size n that contains the same data
  as does chunk p up to the minimum of (n, p's size) bytes, or null
  if no space is available.

  The returned pointer may or may not be the same as p. The algorithm
  prefers extending p when possible, otherwise it employs the
  equivalent of a malloc-copy-free sequence.

  If p is null, realloc is equivalent to malloc.

  If space is not available, realloc returns null, errno is set (if on
  ANSI) and p is NOT freed.

  if n is for fewer bytes than already held by p, the newly unused
  space is lopped off and freed if possible.  Unless the #define
  REALLOC_ZERO_BYTES_FREES is set, realloc with a size argument of
  zero (re)allocates a minimum-sized chunk.

  Large chunks that were internally obtained via mmap will always be
  grown using malloc-copy-free sequences unless the system supports
  MREMAP (currently only linux).

  The old unix realloc convention of allowing the last-free'd chunk
  to be used as an argument to realloc is not supported.
*/
void*  __libc_realloc(void*, size_t);
libc_hidden_proto (__libc_realloc)

/*
  memalign(size_t alignment, size_t n);
  Returns a pointer to a newly allocated chunk of n bytes, aligned
  in accord with the alignment argument.

  The alignment argument should be a power of two. If the argument is
  not a power of two, the nearest greater power is used.
  8-byte alignment is guaranteed by normal malloc calls, so don't
  bother calling memalign with an argument of 8 or less.

  Overreliance on memalign is a sure way to fragment space.
*/
void*  __libc_memalign(size_t, size_t);
libc_hidden_proto (__libc_memalign)

/*
  valloc(size_t n);
  Equivalent to memalign(pagesize, n), where pagesize is the page
  size of the system. If the pagesize is unknown, 4096 is used.
*/
void*  __libc_valloc(size_t);



/*
  mallinfo()
  Returns (by copy) a struct containing various summary statistics:

  arena:     current total non-mmapped bytes allocated from system
  ordblks:   the number of free chunks
  smblks:    the number of fastbin blocks (i.e., small chunks that
	       have been freed but not use resused or consolidated)
  hblks:     current number of mmapped regions
  hblkhd:    total bytes held in mmapped regions
  usmblks:   always 0
  fsmblks:   total bytes held in fastbin blocks
  uordblks:  current total allocated space (normal or mmapped)
  fordblks:  total free space
  keepcost:  the maximum number of bytes that could ideally be released
	       back to system via malloc_trim. ("ideally" means that
	       it ignores page restrictions etc.)

  Because these fields are ints, but internal bookkeeping may
  be kept as longs, the reported values may wrap around zero and
  thus be inaccurate.
*/
struct mallinfo2 __libc_mallinfo2(void);
libc_hidden_proto (__libc_mallinfo2)

struct mallinfo __libc_mallinfo(void);


/*
  pvalloc(size_t n);
  Equivalent to valloc(minimum-page-that-holds(n)), that is,
  round up n to nearest pagesize.
 */
void*  __libc_pvalloc(size_t);

/*
  malloc_trim(size_t pad);

  If possible, gives memory back to the system (via negative
  arguments to sbrk) if there is unused memory at the `high' end of
  the malloc pool. You can call this after freeing large blocks of
  memory to potentially reduce the system-level memory requirements
  of a program. However, it cannot guarantee to reduce memory. Under
  some allocation patterns, some large free blocks of memory will be
  locked between two used chunks, so they cannot be given back to
  the system.

  The `pad' argument to malloc_trim represents the amount of free
  trailing space to leave untrimmed. If this argument is zero,
  only the minimum amount of memory to maintain internal data
  structures will be left (one page or less). Non-zero arguments
  can be supplied to maintain enough trailing space to service
  future expected allocations without having to re-obtain memory
  from the system.

  Malloc_trim returns 1 if it actually released any memory, else 0.
  On systems that do not support "negative sbrks", it will always
  return 0.
*/
int      __malloc_trim(size_t);

/*
  malloc_usable_size(void* p);

  Returns the number of bytes you can actually use in
  an allocated chunk, which may be more than you requested (although
  often not) due to alignment and minimum size constraints.
  You can use this many bytes without worrying about
  overwriting other allocated objects. This is not a particularly great
  programming practice. malloc_usable_size can be more useful in
  debugging and assertions, for example:

  p = malloc(n);
  assert(malloc_usable_size(p) >= 256);

*/
size_t   __malloc_usable_size(void*);

/*
  malloc_stats();
  Prints on stderr the amount of space obtained from the system (both
  via sbrk and mmap), the maximum amount (which may be more than
  current if malloc_trim and/or munmap got called), and the current
  number of bytes allocated via malloc (or realloc, etc) but not yet
  freed. Note that this is the number of bytes allocated, not the
  number requested. It will be larger than the number requested
  because of alignment and bookkeeping overhead. Because it includes
  alignment wastage as being in use, this figure may be greater than
  zero even when no user-level chunks are allocated.

  The reported current and maximum system memory can be inaccurate if
  a program makes other calls to system memory allocation functions
  (normally sbrk) outside of malloc.

  malloc_stats prints only the most commonly interesting statistics.
  More information can be obtained by calling mallinfo.

*/
void     __malloc_stats(void);

/*
  posix_memalign(void **memptr, size_t alignment, size_t size);

  POSIX wrapper like memalign(), checking for validity of size.
*/
int      __posix_memalign(void **, size_t, size_t);
#endif /* IS_IN (libc) */

/*
  mallopt(int parameter_number, int parameter_value)
  Sets tunable parameters The format is to provide a
  (parameter-number, parameter-value) pair.  mallopt then sets the
  corresponding parameter to the argument value if it can (i.e., so
  long as the value is meaningful), and returns 1 if successful else
  0.  SVID/XPG/ANSI defines four standard param numbers for mallopt,
  normally defined in malloc.h.  Only one of these (M_MXFAST) is used
  in this malloc. The others (M_NLBLKS, M_GRAIN, M_KEEP) don't apply,
  so setting them has no effect. But this malloc also supports four
  other options in mallopt. See below for details.  Briefly, supported
  parameters are as follows (listed defaults are for "typical"
  configurations).

  Symbol            param #   default    allowed param values
  M_MXFAST          1         64         0-80  (0 disables fastbins)
  M_TRIM_THRESHOLD -1         128*1024   any   (-1U disables trimming)
  M_TOP_PAD        -2         0          any
  M_MMAP_THRESHOLD -3         128*1024   any   (or 0 if no MMAP support)
  M_MMAP_MAX       -4         65536      any   (0 disables use of mmap)
*/
int      __libc_mallopt(int, int);
#if IS_IN (libc)
libc_hidden_proto (__libc_mallopt)
#endif

/* mallopt tuning options */

/*
  M_MXFAST is the maximum request size used for "fastbins", special bins
  that hold returned chunks without consolidating their spaces. This
  enables future requests for chunks of the same size to be handled
  very quickly, but can increase fragmentation, and thus increase the
  overall memory footprint of a program.

  This malloc manages fastbins very conservatively yet still
  efficiently, so fragmentation is rarely a problem for values less
  than or equal to the default.  The maximum supported value of MXFAST
  is 80. You wouldn't want it any higher than this anyway.  Fastbins
  are designed especially for use with many small structs, objects or
  strings -- the default handles structs/objects/arrays with sizes up
  to 8 4byte fields, or small strings representing words, tokens,
  etc. Using fastbins for larger objects normally worsens
  fragmentation without improving speed.

  M_MXFAST is set in REQUEST size units. It is internally used in
  chunksize units, which adds padding and alignment.  You can reduce
  M_MXFAST to 0 to disable all use of fastbins.  This causes the malloc
  algorithm to be a closer approximation of fifo-best-fit in all cases,
  not just for larger requests, but will generally cause it to be
  slower.
*/


/* M_MXFAST is a standard SVID/XPG tuning option, usually listed in malloc.h */
#ifndef M_MXFAST
#define M_MXFAST            1
#endif

#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST     (64 * SIZE_SZ / 4)
#endif


/*
  M_TRIM_THRESHOLD is the maximum amount of unused top-most memory
  to keep before releasing via malloc_trim in free().

  Automatic trimming is mainly useful in long-lived programs.
  Because trimming via sbrk can be slow on some systems, and can
  sometimes be wasteful (in cases where programs immediately
  afterward allocate more large chunks) the value should be high
  enough so that your overall system performance would improve by
  releasing this much memory.

  The trim threshold and the mmap control parameters (see below)
  can be traded off with one another. Trimming and mmapping are
  two different ways of releasing unused memory back to the
  system. Between these two, it is often possible to keep
  system-level demands of a long-lived program down to a bare
  minimum. For example, in one test suite of sessions measuring
  the XF86 X server on Linux, using a trim threshold of 128K and a
  mmap threshold of 192K led to near-minimal long term resource
  consumption.

  If you are using this malloc in a long-lived program, it should
  pay to experiment with these values.  As a rough guide, you
  might set to a value close to the average size of a process
  (program) running on your system.  Releasing this much memory
  would allow such a process to run in memory.  Generally, it's
  worth it to tune for trimming rather tham memory mapping when a
  program undergoes phases where several large chunks are
  allocated and released in ways that can reuse each other's
  storage, perhaps mixed with phases where there are no such
  chunks at all.  And in well-behaved long-lived programs,
  controlling release of large blocks via trimming versus mapping
  is usually faster.

  However, in most programs, these parameters serve mainly as
  protection against the system-level effects of carrying around
  massive amounts of unneeded memory. Since frequent calls to
  sbrk, mmap, and munmap otherwise degrade performance, the default
  parameters are set to relatively high values that serve only as
  safeguards.

  The trim value It must be greater than page size to have any useful
  effect.  To disable trimming completely, you can set to
  (unsigned long)(-1)

  Trim settings interact with fastbin (MXFAST) settings: Unless
  TRIM_FASTBINS is defined, automatic trimming never takes place upon
  freeing a chunk with size less than or equal to MXFAST. Trimming is
  instead delayed until subsequent freeing of larger chunks. However,
  you can still force an attempted trim by calling malloc_trim.

  Also, trimming is not generally possible in cases where
  the main arena is obtained via mmap.

  Note that the trick some people use of mallocing a huge space and
  then freeing it at program startup, in an attempt to reserve system
  memory, doesn't have the intended effect under automatic trimming,
  since that memory will immediately be returned to the system.
*/

#define M_TRIM_THRESHOLD       -1

#ifndef DEFAULT_TRIM_THRESHOLD
#define DEFAULT_TRIM_THRESHOLD (128 * 1024)
#endif

/*
  M_TOP_PAD is the amount of extra `padding' space to allocate or
  retain whenever sbrk is called. It is used in two ways internally:

  * When sbrk is called to extend the top of the arena to satisfy
  a new malloc request, this much padding is added to the sbrk
  request.

  * When malloc_trim is called automatically from free(),
  it is used as the `pad' argument.

  In both cases, the actual amount of padding is rounded
  so that the end of the arena is always a system page boundary.

  The main reason for using padding is to avoid calling sbrk so
  often. Having even a small pad greatly reduces the likelihood
  that nearly every malloc request during program start-up (or
  after trimming) will invoke sbrk, which needlessly wastes
  time.

  Automatic rounding-up to page-size units is normally sufficient
  to avoid measurable overhead, so the default is 0.  However, in
  systems where sbrk is relatively slow, it can pay to increase
  this value, at the expense of carrying around more memory than
  the program needs.
*/

#define M_TOP_PAD              -2
·
#ifndef DEFAULT_TOP_PAD
#define ·DEFAULT_TOP_PAD        (0)
#endif

/*
  MMAP_THRESHOLD_MAX and _MIN are the bounds on the dynamically
  adjusted MMAP_THRESHOLD.
*/

#ifndef DEFAULT_MMAP_THRESHOLD_MIN
#define DEFAULT_MMAP_THRESHOLD_MIN (128 * 1024)
#endif

#ifndef DEFAULT_MMAP_THRESHOLD_MAX
  /* For 32-bit platforms we cannot increase the maximum mmap
     threshold much because it is also the minimum value for the
     maximum heap size and its alignment.  Going above 512k (i.e., 1M
     for new heaps) wastes too much address space.  */
# if __WORDSIZE == 32
#  define DEFAULT_MMAP_THRESHOLD_MAX (512 * 1024)//512K
# else
#  define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))//16/32M
# endif
#endif

/*
  M_MMAP_THRESHOLD is the request size threshold for using mmap()
  to service a request. Requests of at least this size that cannot
  be allocated using already-existing space will be serviced via mmap.
  (If enough normal freed space already exists it is used instead.)

  Using mmap segregates relatively large chunks of memory so that
  they can be individually obtained and released from the host
  system. A request serviced through mmap is never reused by any
  other request (at least not directly; the system may just so
  happen to remap successive requests to the same locations).

  Segregating space in this way has the benefits that:

   1. Mmapped space can ALWAYS be individually released back
      to the system, which helps keep the system level memory
      demands of a long-lived program low.
   2. Mapped memory can never become `locked' between
      other chunks, as can happen with normally allocated chunks, which
      means that even trimming via malloc_trim would not release them.
   3. On some systems with "holes" in address spaces, mmap can obtain
      memory that sbrk cannot.

  However, it has the disadvantages that:

   1. The space cannot be reclaimed, consolidated, and then
      used to service later requests, as happens with normal chunks.
   2. It can lead to more wastage because of mmap page alignment
      requirements
   3. It causes malloc performance to be more dependent on host
      system memory management support routines which may vary in
      implementation quality and may impose arbitrary
      limitations. Generally, servicing a request via normal
      malloc steps is faster than going through a system's mmap.

  The advantages of mmap nearly always outweigh disadvantages for
  "large" chunks, but the value of "large" varies across systems.  The
  default is an empirically derived value that works well in most
  systems.


  Update in 2006:
  The above was written in 2001. Since then the world has changed a lot.
  Memory got bigger. Applications got bigger. The virtual address space
  layout in 32 bit linux changed.

  In the new situation, brk() and mmap space is shared and there are no
  artificial limits on brk size imposed by the kernel. What is more,
  applications have started using transient allocations larger than the
  128Kb as was imagined in 2001.

  The price for mmap is also high now; each time glibc mmaps from the
  kernel, the kernel is forced to zero out the memory it gives to the
  application. Zeroing memory is expensive and eats a lot of cache and
  memory bandwidth. This has nothing to do with the efficiency of the
  virtual memory system, by doing mmap the kernel just has no choice but
  to zero.

  In 2001, the kernel had a maximum size for brk() which was about 800
  megabytes on 32 bit x86, at that point brk() would hit the first
  mmaped shared libaries and couldn't expand anymore. With current 2.6
  kernels, the VA space layout is different and brk() and mmap
  both can span the entire heap at will.

  Rather than using a static threshold for the brk/mmap tradeoff,
  we are now using a simple dynamic one. The goal is still to avoid
  fragmentation. The old goals we kept are
  1) try to get the long lived large allocations to use mmap()
  2) really large allocations should always use mmap()
  and we're adding now:
  3) transient allocations should use brk() to avoid forcing the kernel
     having to zero memory over and over again

  The implementation works with a sliding threshold, which is by default
  limited to go between 128Kb and 32Mb (64Mb for 64 bitmachines) and starts
  out at 128Kb as per the 2001 default.

  This allows us to satisfy requirement 1) under the assumption that long
  lived allocations are made early in the process' lifespan, before it has
  started doing dynamic allocations of the same size (which will
  increase the threshold).

  The upperbound on the threshold satisfies requirement 2)

  The threshold goes up in value when the application frees memory that was
  allocated with the mmap allocator. The idea is that once the application
  starts freeing memory of a certain size, it's highly probable that this is
  a size the application uses for transient allocations. This estimator
  is there to satisfy the new third requirement.

*/

#define M_MMAP_THRESHOLD      -3

#ifndef DEFAULT_MMAP_THRESHOLD
#define DEFAULT_MMAP_THRESHOLD DEFAULT_MMAP_THRESHOLD_MIN
#endif

/*
  M_MMAP_MAX is the maximum number of requests to simultaneously
  service using mmap. This parameter exists because
  some systems have a limited number of internal tables for
  use by mmap, and using more than a few of them may degrade
  performance.

  The default is set to a value that serves only as a safeguard.
  Setting to 0 disables use of mmap for servicing large requests.
*/

#define M_MMAP_MAX             -4

#ifndef DEFAULT_MMAP_MAX
#define DEFAULT_MMAP_MAX       (65536)
#endif

#include <malloc.h>

#ifndef RETURN_ADDRESS
#define RETURN_ADDRESS(X_) (NULL)
#endif

/* Forward declarations.  */
struct malloc_chunk;
typedef struct malloc_chunk* mchunkptr;

/* Internal routines.  */

static void*  _int_malloc(mstate, size_t);
static void     _int_free(mstate, mchunkptr, int);
static void*  _int_realloc(mstate, mchunkptr, INTERNAL_SIZE_T,
			   INTERNAL_SIZE_T);
static void*  _int_memalign(mstate, size_t, size_t);
#if IS_IN (libc)
static void*  _mid_memalign(size_t, size_t, void *);
#endif

static void malloc_printerr(const char *str) __attribute__ ((noreturn));

static void munmap_chunk(mchunkptr p);
#if HAVE_MREMAP
static mchunkptr mremap_chunk(mchunkptr p, size_t new_size);
#endif

/* ------------------ MMAP support ------------------  */


#include <fcntl.h>
#include <sys/mman.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
# define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef MAP_NORESERVE
# define MAP_NORESERVE 0
#endif

#define MMAP(addr, size, prot, flags) \
 __mmap((addr), (size), (prot), (flags)|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)


/*
  -----------------------  Chunk representations -----------------------
*/


/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/

struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};


/*
   malloc_chunk details:

    (The following includes lightly edited explanations by Colin Plumb.)

    Chunks of memory are maintained using a `boundary tag' method as
    described in e.g., Knuth or Standish.  (See the paper by Paul
    Wilson ftp://ftp.cs.utexas.edu/pub/garbage/allocsrv.ps for a
    survey of such techniques.)  Sizes of free chunks are stored both
    in the front of each chunk and at the end.  This makes
    consolidating fragmented chunks into bigger chunks very fast.  The
    size fields also hold bits representing whether chunks are free or
    in use.

    An allocated chunk looks like this:


    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             User data starts here...                          .
	    .                                                               .
	    .             (malloc_usable_size() bytes)                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             (size of chunk, but used for application data)    |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|1|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Where "chunk" is the front of the chunk for the purpose of most of
    the malloc code, but "mem" is the pointer that is returned to the
    user.  "Nextchunk" is the beginning of the next contiguous chunk.

    Chunks always begin on even word boundaries, so the mem portion
    (which is returned to the user) is also on an even word boundary, and
    thus at least double-word aligned.

    Free chunks are stored in circular doubly-linked lists, and look like this:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Forward pointer to next chunk in list             |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Back pointer to previous chunk in list            |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Unused space (may be 0 bytes long)                .
	    .                                                               .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|0|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    The P (PREV_INUSE) bit, stored in the unused low-order bit of the
    chunk size (which is always a multiple of two words), is an in-use
    bit for the *previous* chunk.  If that bit is *clear*, then the
    word before the current chunk size contains the previous chunk
    size, and can be used to find the front of the previous chunk.
    The very first chunk allocated always has this bit set,
    preventing access to non-existent (or non-owned) memory. If
    prev_inuse is set for any given chunk, then you CANNOT determine
    the size of the previous chunk, and might even get a memory
    addressing fault when trying to do so.

    The A (NON_MAIN_ARENA) bit is cleared for chunks on the initial,
    main arena, described by the main_arena variable.  When additional
    threads are spawned, each thread receives its own arena (up to a
    configurable limit, after which arenas are reused for multiple
    threads), and the chunks in these arenas have the A bit set.  To
    find the arena for a chunk on such a non-main arena, heap_for_ptr
    performs a bit mask operation and indirection through the ar_ptr
    member of the per-heap header heap_info (see arena.c).

    Note that the `foot' of the current chunk is actually represented
    as the prev_size of the NEXT chunk. This makes it easier to
    deal with alignments etc but can be very confusing when trying
    to extend or adapt this code.

    The three exceptions to all this are:

     1. The special chunk `top' doesn't bother using the
	trailing size field since there is no next contiguous chunk
	that would have to index off it. After initialization, `top'
	is forced to always exist.  If it would become less than
	MINSIZE bytes long, it is replenished.

     2. Chunks allocated via mmap, which have the second-lowest-order
	bit M (IS_MMAPPED) set in their size fields.  Because they are
	allocated one-by-one, each must contain its own trailing size
	field.  If the M bit is set, the other bits are ignored
	(because mmapped chunks are neither in an arena, nor adjacent
	to a freed chunk).  The M bit is also used for chunks which
	originally came from a dumped heap via malloc_set_state in
	hooks.c.

     3. Chunks in fastbins are treated as allocated chunks from the
	point of view of the chunk allocator.  They are consolidated
	with their neighbors only in bulk, in malloc_consolidate.
*/

/*
  ---------- Size and alignment checks and conversions ----------
*/

/* Conversion from malloc headers to user pointers, and back.  When
   using memory tagging the user data and the malloc data structure
   headers have distinct tags.  Converting fully from one to the other
   involves extracting the tag at the other address and creating a
   suitable pointer using it.  That can be quite expensive.  There are
   cases when the pointers are not dereferenced (for example only used
   for alignment check) so the tags are not relevant, and there are
   cases when user data is not tagged distinctly from malloc headers
   (user data is untagged because tagging is done late in malloc and
   early in free).  User memory tagging across internal interfaces:

      sysmalloc: Returns untagged memory.
      _int_malloc: Returns untagged memory.
      _int_free: Takes untagged memory.
      _int_memalign: Returns untagged memory.
      _int_memalign: Returns untagged memory.
      _mid_memalign: Returns tagged memory.
      _int_realloc: Takes and returns tagged memory.
*/

/* The chunk header is two SIZE_SZ elements, but this is used widely, so
   we define it here for clarity later.  */
   //说明CHUNK头是包含    mchunk_prev_size以及 mchunk_size;    
   //没有规定SIZE_SZ是32/64,即使64位中，定义它为32位，好像也没什么大的问题，因为32未表示大小基本足够
   //#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))    ;    INTERNAL_SIZE_T might be signed or unsigned, might be 32 or 64 bits,
#define CHUNK_HDR_SZ (2 * SIZE_SZ)

/* Convert a chunk address to a user mem pointer without correcting
   the tag.  */
#define chunk2mem(p) ((void*)((char*)(p) + CHUNK_HDR_SZ))

/* Convert a chunk address to a user mem pointer and extract the right tag.  */
#define chunk2mem_tag(p) ((void*)tag_at ((char*)(p) + CHUNK_HDR_SZ))

/* Convert a user mem pointer to a chunk address and extract the right tag.  */
#define mem2chunk(mem) ((mchunkptr)tag_at (((char*)(mem) - CHUNK_HDR_SZ)))

/* The smallest possible chunk */
//最小值为2个头部数据（32/64都可能）以及两个指针数据(指针一般而言32位下为4字节，64位下为8字节)，因此其应该是可以为4+4+4+4=16/4+4+8+8=24/8+8+8+8=32
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */
//MALLOC_ALIGNMENT is the minimum alignment for malloc'ed chunks.  It  must be a power of two at least 2 * SIZE_SZ,因此其可以为8B也可以为16B
//#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)  因此其为7/15
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

/* Check if m has acceptable alignment */

#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == CHUNK_HDR_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)

/* pad request bytes into a usable size -- internal version */
/* Note: This must be a macro that evaluates to a compile time constant
   if passed a literal constant.  */
//应该是转换成能容下请求req 的合理的CHUNKSIZE大小,考虑了chunk之后的下一个chunk的prev_size空间做为req使用
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)//MALLOC_ALIGN_MASK=2*SIZE-1

/* Check if REQ overflows when padded and aligned and if the resulting value
   is less than PTRDIFF_T.  Returns TRUE and the requested size or MINSIZE in
   case the value is less than MINSIZE on SZ or false if any of the previous
   check fail.  */
static inline bool
checked_request2size (size_t req, size_t *sz) __nonnull (1)
{
  if (__glibc_unlikely (req > PTRDIFF_MAX))//PTRDIFF_MAX=2^31/63,检测请求
    return false;

  /* When using tagged memory, we cannot share the end of the user
     block with the header for the next chunk, so ensure that we
     allocate blocks that are rounded up to the granule size.  Take
     care not to overflow from close to MAX_SIZE_T to a small
     number.  Ideally, this would be part of request2size(), but that
     must be a macro that produces a compile time constant if passed
     a constant literal.  */
  if (__glibc_unlikely (mtag_enabled))
    {
      /* Ensure this is not evaluated if !mtag_enabled, see gcc PR 99551.  */
      asm ("");

      req = (req + (__MTAG_GRANULE_SIZE - 1)) &
	    ~(size_t)(__MTAG_GRANULE_SIZE - 1);
    }

  *sz = request2size (req);
  return true;
}

/*
   --------------- Physical chunk operations ---------------
 */


/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->mchunk_size & PREV_INUSE)


/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)


/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* Check for chunk from main arena.  */
#define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)

/* Mark a chunk as not being on the main arena.  */
#define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)


/*
   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size)

/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + chunksize (p)))

/* Size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Set the size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))

/* Ptr to previous physical malloc_chunk.  Only valid if !prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr) (((char *) (p)) - prev_size (p)))

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

/* extract p's inuse bit */
#define inuse(p)							      \
  ((((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size |= PREV_INUSE

#define clear_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size &= ~(PREV_INUSE)


/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))


/* Set size at head, without disturbing its use bit */
//为了方便空闲Chunck进行合并
#define set_head_size(p, s)  ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))

/* Set size/use field */
#define set_head(p, s)       ((p)->mchunk_size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))

#pragma GCC poison mchunk_size
#pragma GCC poison mchunk_prev_size

/* This is the size of the real usable data in the chunk.  Not valid for
   dumped heap chunks.  */
#define memsize(p)                                                    \
  (__MTAG_GRANULE_SIZE > SIZE_SZ && __glibc_unlikely (mtag_enabled) ? \
    chunksize (p) - CHUNK_HDR_SZ :                                    \//没启用mtag时，会利用下一个chunk头部的mchunk_prev_size
    chunksize (p) - CHUNK_HDR_SZ + (chunk_is_mmapped (p) ? 0 : SIZE_SZ))//看上去好像是如果不是mmap分配的即brk分配的（MAIN  ARENA ），那么会利用上下一个Chunk 的头部mchunk_prev_size

/* If memory tagging is enabled the layout changes to accommodate the granule
   size, this is wasteful for small allocations so not done by default.
   Both the chunk header and user data has to be granule aligned.  */
_Static_assert (__MTAG_GRANULE_SIZE <= CHUNK_HDR_SZ,
		"memory tagging is not supported with large granule.");

static __always_inline void *
tag_new_usable (void *ptr)
{//mtag和arm有关，暂不分析，此方法相当于直接返回参数指针
  if (__glibc_unlikely (mtag_enabled) && ptr)
    {
      mchunkptr cp = mem2chunk(ptr);
      ptr = __libc_mtag_tag_region (__libc_mtag_new_tag (ptr), memsize (cp));
    }
  return ptr;
}

/*
   -------------------- Internal data structures --------------------

   All internal state is held in an instance of malloc_state defined
   below. There are no other static variables, except in two optional
   cases:
 * If USE_MALLOC_LOCK is defined, the mALLOC_MUTEx declared above.
 * If mmap doesn't support MAP_ANONYMOUS, a dummy file descriptor
     for mmap.

   Beware of lots of tricks that minimize the total bookkeeping space
   requirements. The result is a little over 1K bytes (for 4byte
   pointers and size_t.)
 */

/*
   Bins

  //Free Chuncks的header组成的Arrary
  //双链表
  //128个Bin，这些bin大致成对数比例
  //FreeChunk不会物理相邻，前/后一个块为INUSE或者为the ends of Memory
    An array of bin headers for free chunks. Each bin is doubly
    linked.  The bins are approximately proportionally (log) spaced.
    There are a lot of these bins (128). This may look excessive, but
    works very well in practice.  Most bins hold sizes that are
    unusual as malloc request sizes, but are more usual for fragments
    and consolidated sets of chunks, which is what these bins hold, so
    they can be found quickly.  All procedures maintain the invariant
    that no consolidated chunk physically borders another one, so each
    chunk in a list is known to be preceeded and followed by either
    inuse chunks or the ends of memory.

    Chunks in bins are kept in size order, with ties going to the
    approximately least recently used chunk. Ordering isn't needed
    for the small bins, which all contain the same-sized chunks, but
    facilitates best-fit allocation for larger chunks. These lists
    are just sequential. Keeping them in order almost never requires
    enough traversal to warrant using fancier ordered data
    structures.
//先进先出，让每一个块都有相同的机会和相邻的Free块进行合并
    Chunks of the same size are linked with the most
    recently freed at the front, and allocations are taken from the
    back.  This results in LRU (FIFO) allocation order, which tends
    to give each chunk an equal opportunity to be consolidated with
    adjacent freed chunks, resulting in larger free chunks and less
    fragmentation.
//只使用了fd,bk指针表示一个头，但是用起来的时候，却是当成一整个malloc_chunk来使用
    To simplify use in double-linked lists, each bin header acts
    as a malloc_chunk. This avoids special-casing for headers.
    But to conserve space and improve locality, we allocate
    only the fd/bk pointers of bins, and then use repositioning tricks
    to treat these as the fields of a malloc_chunk*.
 */

typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
//bins[NBINS * 2 - 2],NBINS=128, 里面一共可视为127个malloc_chunk链表，使用起来时i范围在1-127（底层对应0-126 chunk链表）
//&bins[0]-2*SIZE  ，将这个地址视为malloc_Chunk，这样可以方便的通过->fd,fk进行访问bin中包含的chunk
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))			      \
             - offsetof (struct malloc_chunk, fd))

/* analog of ++bin */
//原地址+指针大小乘以2,相当于移动到了下一个bin
#define next_bin(b)  ((mbinptr) ((char *) (b) + (sizeof (mchunkptr) << 1)))

/* Reminders about list directionality within bins */
//访问指定bin 中的第一个/最后一个 chunck
#define first(b)     ((b)->fd)
#define last(b)      ((b)->bk)

/*
   Indexing
  //
    Bins for sizes < 512 bytes contain chunks of all the same size, spaced
    8 bytes apart. Larger bins are approximately logarithmically spaced:
    //近似对数关系增长

    64 bins of size       8             8B                 
    32 bins of size      64            64B
    16 bins of size     512           0.5K
     8 bins of size    4096           4K
     4 bins of size   32768          4*8K
     2 bins of size  262144         256K
     1 bin  of size what's left
     sum   127<128
    There is actually a little bit of slop in the numbers in bin_index
    for the sake of speed. This makes no difference elsewhere.

    The bins top out around 1MB because we expect to service large
    requests via mmap.
    //bins 0 不存在，bins 1 是 unsorted list
    Bin 0 does not exist.  Bin 1 is the unordered list; if that would be
    a valid chunk size the small bins are bumped up one.
 */

//  mchunkptr bins[NBINS * 2 - 2]; 查找时bins[((i) - 1) * 2])为查找方式，i能表示1-127
#define NBINS             128
#define NSMALLBINS         64    //SMALLBINS占据64个
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT   //一般即为2×SIZE_SZ，相当于一个CHUNK_HDR_SZ，好像是上面注释中8B 对应的含义
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > CHUNK_HDR_SZ)   //感觉一般而言是一样的，也就是0
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)   //像是得到LARGE BINS中最小值  64*2*SIZE_SZ(SIZE_SZ可以为4B也可以为8B )

#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)//判断是否在smallbin范围内，这个逻辑来看，好像SMALL BIN  最大为63*2*SIZE_SZ<MIN_LARGE_SIZE= 64*2*SIZE_SZ

#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)//一般而言，SMALLBIN_WIDTH要么为16要么为8,将字节数/SMALLBIN_WIDTH就是Index

#define largebin_index_32(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 38) ?  56 + (((unsigned long) (sz)) >> 6) :\ //sz/64 <= 38?56+sz/64:    sz>=512  bins[64-94]
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\ //sz/512<=20?91+sz/512:  
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\ //sz/4096<=10?110+sz/4096
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\ //sz/(32*1024)<=4?119+sz/(32*1024)
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\ //sz/256K<=2?124+sz/256K
   126)

#define largebin_index_32_big(sz)                                            \
  (((((unsigned long) (sz)) >> 6) <= 45) ?  49 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
// 与largebin_index_32好像就第一行不同
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

//一般而言MALLOC_ALIGNMENT=2×SIZE_SZ
//这里相当于SIZE_SZ=8时，largebin_index_64;SIZE_SZ=4时largebin_index_32
#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))
//通过size 计算在bin中的索引
#define bin_index(sz) \
  ((in_smallbin_range (sz)) ? smallbin_index (sz) : largebin_index (sz))

/* Take a chunk off a bin list.  */
// 如果unsortedbin和smallbin，则只维护fd/bk双链表
// 如果是largebin，则除了维护fd/bk双链表，还要维护fd/bk_nextsize双链表
static void
unlink_chunk (mstate av, mchunkptr p)
{
  //check
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;
 //check
  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");
  //处理p被取出后的fd/bk指针
  fd->bk = bk;
  bk->fd = fd;
  //在large bin 中，fd_nextsize不为null，进一步处理，设置fd_nextsize bk_nextsize 相关；注意unsortedbin中的largechunk的fd/bk_nextsize却为NULL，这个关系仅在largebin中维护
  // 感觉像是相同size chunk的继承前一个（也是第一个）的next_size指针，只在每个bin的第一个chunk之间连接
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
      if (p->fd_nextsize->bk_nextsize != p
	  || p->bk_nextsize->fd_nextsize != p)
	malloc_printerr ("corrupted double-linked list (not small)");
      //通常有fd_nextsize的chunk为相邻的相同大小chunks中的第一个（其它chunk没有fd_nextsize）
      //现在是在移除p的情况下，继续维护fd_nextsize和bk_nextsize;
      if (fd->fd_nextsize == NULL)
	{
	  if (p->fd_nextsize == p)//fd/bk_nextsize级别的双链表只有一个元素
	    fd->fd_nextsize = fd->bk_nextsize = fd;
	  else
	    {
	      fd->fd_nextsize = p->fd_nextsize;//fd应该是同大小的large chunk组中的第一个了
	      fd->bk_nextsize = p->bk_nextsize;
	      p->fd_nextsize->bk_nextsize = fd;
	      p->bk_nextsize->fd_nextsize = fd;
	    }
	}
      else
	{
	  p->fd_nextsize->bk_nextsize = p->bk_nextsize;
	  p->bk_nextsize->fd_nextsize = p->fd_nextsize;
	}
    }
}

/*
   Unsorted chunks
    //来源：split chunk/returned chunk(应该是指free)
    All remainders from chunk splits, as well as all returned chunks,
    are first placed in the "unsorted" bin. They are then placed
    in regular bins after malloc gives them ONE chance to be used before
    binning. So, basically, the unsorted_chunks list acts as a queue,
    with chunks being placed on it in free ( and malloc_consolidate),
    and taken off (to be either used or placed in bins) in malloc.
    //不会被设置NON_MAIN_ARENA标识
    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
    does not have to be taken into account in size comparisons.
 */

/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
//使用上意义为1(1-127)的位置为unsorted bin，实际是bins[0]
#define unsorted_chunks(M)          (bin_at (M, 1))

/*
   Top
    //界定可用内存的结尾，并被特殊对待
    //它不在任何bin中，只有在其它chunk不可用时，才被使用。
    //并且当top 特别大时（参考紧缩限制M_TRIM_THRESHOLD），会释放占有的内存给操作系统
    //初始时为0,在第一次malloc request 时，强制扩展
    //为了避免使用一些特殊的代码，将unsorted bin can be used as dummy(仿制) top on first call 
    The top-most available chunk (i.e., the one bordering the end of
    available memory) is treated specially. It is never included in
    any bin, is used only if no other chunk is available, and is
    released back to the system if it is very large (see
    M_TRIM_THRESHOLD).  Because top initially
    points to its own bin with initial zero size, thus forcing
    extension on the first malloc request, we avoid having any special
    code in malloc to check whether it even exists yet. But we still
    need to do so when getting memory from system, so we make
    initial_top treat the bin as a legal but unusable chunk during the
    interval between initialization and the first call to
    sysmalloc. (This is somewhat delicate, since it relies on
    the 2 preceding words to be zero during this interval as well.)
 */

/* Conveniently, the unsorted bin can be used as dummy top on first call */
#define initial_top(M)              (unsorted_chunks (M))

/*
   Binmap
    //帮助在遍历时索引
    To help compensate for the large number of bins, a one-level index
    structure is used for bin-by-bin searching.  `binmap' is a
    bitvector recording whether bins are definitely empty so they can
    be skipped over during during traversals.  The bits are NOT always
    cleared as soon as bins are empty, but instead only
    when they are noticed to be empty during traversal in malloc.
 */

/* Conservatively use 32 bits per map word, even if on 64bit system */
#define BINMAPSHIFT      5
#define BITSPERMAP       (1U << BINMAPSHIFT)
#define BINMAPSIZE       (NBINS / BITSPERMAP)

#define idx2block(i)     ((i) >> BINMAPSHIFT)
#define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

#define mark_bin(m, i)    ((m)->binmap[idx2block (i)] |= idx2bit (i))
#define unmark_bin(m, i)  ((m)->binmap[idx2block (i)] &= ~(idx2bit (i)))
#define get_binmap(m, i)  ((m)->binmap[idx2block (i)] & idx2bit (i))

/*
   Fastbins
  //存放最近释放的small chunks
  //单链表 LIFO
    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.
  //fastbin对应的inuse位始终被设置（下一个物理相邻的 chunk 的 P 位），防止和其它free chunk合并
  //但malloc_consolidate会释放fastbin并允许它们与其它free chunks进行合并
    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */

typedef struct malloc_chunk *mfastbinptr;
//ar_ptr 即arena ptr ，数据结构：malloc_state
//从mstate获取指定索引的fastbin
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
//通过sz获取所属fastbin的索引
//-2的偏移，是为了让最小chunk size除完后能够定位到索引0,类似这样的作用
//sz 是Chunk的大小，通常会先用request2size转换成Chunk大小再计算索引
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)


/* The maximum fastbin request size we support */
//SIZE_SZ=4时，fastbin 最大为80字节
//SIZE_SZ=8时，fastbin最大为160字节
//这里的大小是指用户可用数据区域的大小，而不是Chunk的大小
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)
//计算fastbin需要的数组长度
//这里使用了request2size说明fastbin_index计算索引时是用的Chunk的大小
#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)

/*
   FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
   that triggers automatic consolidation of possibly-surrounding
   fastbin chunks. This is a heuristic, so the exact value should not
   matter too much. It is defined at half the default trim threshold as a
   compromise heuristic to only attempt consolidation if it is likely
   to lead to trimming. However, it is not dynamically tunable, since
   consolidation reduces fragmentation surrounding large chunks even
   if trimming is not used.
 */

#define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)

/*意味着MORECORE 不返回相邻region，暂不清楚用在哪里
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.

   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */

#define NONCONTIGUOUS_BIT     (2U)

#define contiguous(M)          (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M)       (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M)   ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M)      ((M)->flags &= ~NONCONTIGUOUS_BIT)

/* Maximum size of memory handled in fastbins.  */
static INTERNAL_SIZE_T global_max_fast;

/*
   Set value of max_fast.
   Use impossibly small value if 0.
   Precondition: there are no existing fastbin chunks in the main arena.
   Since do_check_malloc_state () checks this, we call malloc_consolidate ()
   before changing max_fast.  Note other arenas will leak their fast bin
   entries if max_fast is reduced.
 */

#define set_max_fast(s) \
  global_max_fast = (((size_t) (s) <= MALLOC_ALIGN_MASK - SIZE_SZ)	\
                     ? MIN_CHUNK_SIZE / 2 : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))

static inline INTERNAL_SIZE_T
get_max_fast (void)
{
  /* Tell the GCC optimizers that global_max_fast is never larger
     than MAX_FAST_SIZE.  This avoids out-of-bounds array accesses in
     _int_malloc after constant propagation of the size parameter.
     (The code never executes because malloc preserves the
     global_max_fast invariant, but the optimizers may not recognize
     this.)  */
  if (global_max_fast > MAX_FAST_SIZE)
    __builtin_unreachable ();
  return global_max_fast;
}

/*
   ----------- Internal state representation and initialization -----------
 */

/*
   have_fastchunks indicates that there are probably some fastbin chunks.
   It is set true on entering a chunk into any fastbin, and cleared early in
   malloc_consolidate.  The value is approximate since it may be set when there
   are no fastbin chunks, or it may be clear even if there are fastbin chunks
   available.  Given it's sole purpose is to reduce number of redundant calls to
   malloc_consolidate, it does not affect correctness.  As a result we can safely
   use relaxed atomic accesses.
 */


struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */

  struct malloc_state *next;
  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;//管理的内存
  I NTERNAL_SIZE_T max_system_mem;//历史管理的最大内存
};

struct malloc_par
{
  /* Tunable parameters */
  unsigned long trim_threshold;
  INTERNAL_SIZE_T top_pad;
  INTERNAL_SIZE_T mmap_threshold;
  INTERNAL_SIZE_T arena_test;
  INTERNAL_SIZE_T arena_max;

  /* Memory map support */
  int n_mmaps;
  int n_mmaps_max;
  int max_n_mmaps;
  /* the mmap_threshold is dynamic, until the user sets
     it manually, at which point we need to disable any
     dynamic behavior. */
  int no_dyn_threshold;

  /* Statistics */
  INTERNAL_SIZE_T mmapped_mem;
  INTERNAL_SIZE_T max_mmapped_mem;

  /* First address handed out by MORECORE/sbrk.  */
  // On  success,  sbrk()  returns  the  previous program break. 此地址为brk 区域的起始地址
  char *sbrk_base;

#if USE_TCACHE
  /* Maximum number of buckets to use.  */
  size_t tcache_bins;
  size_t tcache_max_bytes;
  /* Maximum number of chunks in each bucket.  */
  size_t tcache_count;
  /* Maximum number of chunks to remove from the unsorted list, which
     aren't used to prefill the cache.  */
  size_t tcache_unsorted_limit;
#endif
};

/* There are several instances of this struct ("arenas") in this
   malloc.  If you are adapting this malloc in a way that does NOT use
   a static or mmapped malloc_state, you MUST explicitly zero-fill it
   before using. This malloc relies on the property that malloc_state
   is initialized to all zeroes (as is true of C statics).  */
//无论是main_arean还是非main_arena，在刚创建的时候，结构体中默认值为0，除非进一步被初始化了；比如fastbin一开始元素都为NULL;
static struct malloc_state main_arena =
{
  .mutex = _LIBC_LOCK_INITIALIZER,
  .next = &main_arena,
  .attached_threads = 1
};

/* There is only one instance of the malloc parameters.  */

static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
#if USE_TCACHE
  ,
  .tcache_count = TCACHE_FILL_COUNT,
  .tcache_bins = TCACHE_MAX_BINS,
  .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
  .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};

/*
   Initialize a malloc_state struct.
   This is called from ptmalloc_init () //第一次malloc时调用，初始化main arena
   or from _int_new_arena () when creating a new arena.
 */

static void
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;

  /* Establish circular links for normal bins */
  //初始化bins，bin的头结点指向所在chunk自己，相当于初始化为空链表
  //chunk实际不存在，只是为了方便计算地址，而且用于表示链表头
  for (i = 1; i < NBINS; ++i)
    {
      bin = bin_at (av, i);
      bin->fd = bin->bk = bin;
    }
//MORECORE->sbrk
//MORECORE_CONTIGUOUS为1,就是说定义了sbrk（sbrk区域是连续的）
//如果定义了sbrk，那么非主分区默认就是非连续的，主分区默认是连续的；
//主分区第一次因为brk不足而mmap时，就会变成非连续了（但是如果是因为mmap_threshold而mmap则还是连续的）
#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif
  set_noncontiguous (av);//设置非连续标志；
  if (av == &main_arena)//av为主分区仅仅在第一次时会走此路径，设置global_max_fast
     //Maximum size of memory handled in fastbins.
     //在SIZE_SZ=4时，global_max_fast=64；在SIZE_SZ=8时，global_max_fast=128；通常为128
    set_max_fast (DEFAULT_MXFAST);
  atomic_store_relaxed (&av->have_fastchunks, false);//设置av->have_fastchunks=0
  //av->top = &(av->bins[0]) - offsetof (struct malloc_chunk, fd))
  //初始化top值为unsortedbin对应的链表头
  av->top = initial_top (av);
}

/*
   Other internal utilities operating on mstates
 */

static void *sysmalloc (INTERNAL_SIZE_T, mstate);
static int      systrim (size_t, mstate);
static void     malloc_consolidate (mstate);


/* -------------- Early definitions for debugging hooks ---------------- */

/* This function is called from the arena shutdown hook, to free the
   thread cache (if it exists).  */
static void tcache_thread_shutdown (void);

/* ------------------ Testing support ----------------------------------*/

static int perturb_byte;

static void
alloc_perturb (char *p, size_t n)
{
  if (__glibc_unlikely (perturb_byte))//如果perturb_byte存在，则memst一些字节
    memset (p, perturb_byte ^ 0xff, n);
}

static void
free_perturb (char *p, size_t n)
{
  if (__glibc_unlikely (perturb_byte))//目前来看，全局静态变量应该默认是0
    memset (p, perturb_byte, n);
}



#include <stap-probe.h>

/* ------------------- Support for multiple arenas -------------------- */
#include "arena.c"

/*
   Debugging support

   These routines make a number of assertions about the states
   of data structures that should be true at all times. If any
   are not true, it's very likely that a user program has somehow
   trashed memory. (It's also possible that there is a coding error
   in malloc. In which case, please report it!)
 */

#if !MALLOC_DEBUG //默认为0,不做这些检测

# define check_chunk(A, P)
# define check_free_chunk(A, P)
# define check_inuse_chunk(A, P)
# define check_remalloced_chunk(A, P, N)
# define check_malloced_chunk(A, P, N)
# define check_malloc_state(A)

#else

# define check_chunk(A, P)              do_check_chunk (A, P)
# define check_free_chunk(A, P)         do_check_free_chunk (A, P)
# define check_inuse_chunk(A, P)        do_check_inuse_chunk (A, P)
# define check_remalloced_chunk(A, P, N) do_check_remalloced_chunk (A, P, N)
# define check_malloced_chunk(A, P, N)   do_check_malloced_chunk (A, P, N)
# define check_malloc_state(A)         do_check_malloc_state (A)

/*
   Properties of all chunks
 */

static void
do_check_chunk (mstate av, mchunkptr p)//所有chunk都检查的属性
{
  unsigned long sz = chunksize (p);
  /* min and max possible addresses assuming contiguous allocation */
  char *max_address = (char *) (av->top) + chunksize (av->top);//假定连续分配时的最大的地址
  char *min_address = max_address - av->system_mem;//假定连续分配时的最小的地址
  //mmaped情形：超过了mmap_threshold阈值；
  //brk中分配不会，非主分配区的heap(mmaped出来的区域)分配也不会设置
  //注意：主分配区因为brk不足，新mmap出来的区域(此时住分配区变成非连续了)，其中chunk不会被标记为is_mmapped,所以如果brk分配了新的地
  if (!chunk_is_mmapped (p))//不是通过mmap分配的，也就是通过sbrk区域分配的;mmap 时总会设置IS_MMAPPED标识
    {
      /* Has legal address ... */
      if (p != av->top)//如果p不是top chunk
        {
          //如果定义了sbrk，那么非主分区默认就是非连续的，主分区默认是连续的；
          //主分区第一次因为brk不足而mmap时，就会变成非连续了（但是如果是因为mmap_threshold而mmap则还是连续的）
          if (contiguous (av))//如果av是连续的，从来没有分配过mmap
            {//必然大于最小地址且小于topchunk地址
              assert (((char *) p) >= min_address);
              assert (((char *) p + sz) <= ((char *) (av->top)));
            }
        }
      else
        {
          /* top size is always at least MINSIZE */
          assert ((unsigned long) (sz) >= MINSIZE);//top必须大于等于MINSIZE
          /* top predecessor always marked inuse */
          assert (prev_inuse (p));//top的前置必须为inuse
        }
    }
  else
    {//mmap；
      /* address is outside main heap  */
      if (contiguous (av) && av->top != initial_top (av))//非主分区默认就是非连续；主分区的话，在一定条件下，也可能从连续变成非连续
        {
          assert (((char *) p) < min_address || ((char *) p) >= max_address);//判断主分区的heap区域
        }
      /* chunk is page-aligned */
      assert (((prev_size (p) + sz) & (GLRO (dl_pagesize) - 1)) == 0);//mmap区域必须页对齐
      /* mem is aligned */
      assert (aligned_OK (chunk2mem (p)));//chunk必须MALLOC_ALIGN对齐
    }
}

/*
   Properties of free chunks
 */

static void
do_check_free_chunk (mstate av, mchunkptr p)//free chunk的检查
{
  INTERNAL_SIZE_T sz = chunksize_nomask (p) & ~(PREV_INUSE | NON_MAIN_ARENA);
  mchunkptr next = chunk_at_offset (p, sz);

  do_check_chunk (av, p);//检测紧挨着的下一个chunk

  /* Chunk must claim to be free ... */
  assert (!inuse (p));//p没在使用
  assert (!chunk_is_mmapped (p));//p不是mmaped;这里也说明mmap的chunk好像不走这个检查；另外在munmap_chunk方法中也可以看到，没有当前方法的检查

  /* Unless a special marker, must have OK fields */
  if ((unsigned long) (sz) >= MINSIZE)//正常的chunk检查
    {
      assert ((sz & MALLOC_ALIGN_MASK) == 0);//sz大小对其检测
      assert (aligned_OK (chunk2mem (p)));//mem对齐检测
      /* ... matching footer field */
      assert (prev_size (next_chunk (p)) == sz);//prev_size检测
      /* ... and is fully consolidated */
      assert (prev_inuse (p));//prev_inuse检测
      //下一个chunk为top或者下下一个chunk的prev_inuse为true
      assert (next == av->top || inuse (next));

      /* ... and has minimally sane links */
      assert (p->fd->bk == p);
      assert (p->bk->fd == p);//链表检测
    }
  else /* markers are always of size SIZE_SZ */  //marker是指什么？fencepost也不太像啊，暂不清楚
    assert (sz == SIZE_SZ);
}

/*
   Properties of inuse chunks
 */

static void
do_check_inuse_chunk (mstate av, mchunkptr p)//对于使用中的chunk的检测
{
  mchunkptr next;

  do_check_chunk (av, p);//一般的属性检测

  if (chunk_is_mmapped (p))//mmapedchunk 没有前后chunk，直接返回
    return; /* mmapped chunks have no next/prev */

  /* Check whether it claims to be in use ... */
  assert (inuse (p));//p必须处于inuse状态

  next = next_chunk (p);

  /* ... and is surrounded by OK chunks.
     Since more things can be checked with free chunks than inuse ones,
     if an inuse chunk borders them and debug is on, it's worth doing them.
   */
  if (!prev_inuse (p))//紧挨着的前一个chunk为free时
    {
      /* Note that we cannot even look at prev unless it is not inuse */
      mchunkptr prv = prev_chunk (p);
      assert (next_chunk (prv) == p);//free块的前一个必须为p
      do_check_free_chunk (av, prv);//free块检测
    }

  if (next == av->top)
    {
      assert (prev_inuse (next));//top的prev_inuse必须为true
      assert (chunksize (next) >= MINSIZE);//top大小检测
    }
  else if (!inuse (next))//下一个是空闲块
    do_check_free_chunk (av, next);//空闲块检测
}

/*
   Properties of chunks recycled from fastbins
 */

static void
do_check_remalloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
{
  INTERNAL_SIZE_T sz = chunksize_nomask (p) & ~(PREV_INUSE | NON_MAIN_ARENA);

  if (!chunk_is_mmapped (p))
    {
      assert (av == arena_for_chunk (p));//arena检测
      if (chunk_main_arena (p))
        assert (av == &main_arena);
      else
        assert (av != &main_arena);
    }

  do_check_inuse_chunk (av, p);//使用中的chunk检测

  /* Legal size ... 大小检测*/
  assert ((sz & MALLOC_ALIGN_MASK) == 0);
  assert ((unsigned long) (sz) >= MINSIZE);
  /* ... and alignment 对齐检测*/
  assert (aligned_OK (chunk2mem (p)));
  /* chunk is less than MINSIZE more than request sz范围检测*/
  assert ((long) (sz) - (long) (s) >= 0);
  assert ((long) (sz) - (long) (s + MINSIZE) < 0);
}

/*
   Properties of nonrecycled chunks at the point they are malloced
 */

static void
do_check_malloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
{
  /* same as recycled case ... */
  do_check_remalloced_chunk (av, p, s);

  /*
     ... plus,  must obey implementation invariant that prev_inuse is
     always true of any allocated chunk; i.e., that each allocated
     chunk borders either a previously allocated and still in-use
     chunk, or the base of its memory arena. This is ensured
     by making all allocations from the `lowest' part of any found
     chunk.  This does not necessarily hold however for chunks
     recycled via fastbins.
   */

  assert (prev_inuse (p));//不清楚这个是干嘛的，前一个一定在使用？
}


/*
   Properties of malloc_state.

   This may be useful for debugging malloc, as well as detecting user
   programmer errors that somehow write into malloc_state.

   If you are extending or experimenting with this malloc, you can
   probably figure out how to hack this routine to print out or
   display chunk addresses, sizes, bins, and other instrumentation.
 */

static void
do_check_malloc_state (mstate av)//arena检测
{
  int i;
  mchunkptr p;
  mchunkptr q;
  mbinptr b;
  unsigned int idx;
  INTERNAL_SIZE_T size;
  unsigned long total = 0;
  int max_fast_bin;

  /* internal size_t must be no wider than pointer type */
  assert (sizeof (INTERNAL_SIZE_T) <= sizeof (char *));//指针大小检测

  /* alignment is a power of 2 */
  assert ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT - 1)) == 0);

  /* Check the arena is initialized. */
  assert (av->top != 0);//被初始化过

  /* No memory has been allocated yet, so doing more tests is not possible.  */
  if (av->top == initial_top (av))//指向自己，说明还没有分配过
    return;

  /* pagesize is a power of 2 */
  assert (powerof2(GLRO (dl_pagesize)));

  /* A contiguous main_arena is consistent with sbrk_base.  */
  if (av == &main_arena && contiguous (av))//如果是连续的主分配区，进行检测
    assert ((char *) mp_.sbrk_base + av->system_mem ==
            (char *) av->top + chunksize (av->top));

  /* properties of fastbins */

  /* max_fast is in allowed range max fast bin检测*/
  assert ((get_max_fast () & ~1) <= request2size (MAX_FAST_SIZE));

  max_fast_bin = fastbin_index (get_max_fast ());

  for (i = 0; i < NFASTBINS; ++i)
    {
      p = fastbin (av, i);

      /* The following test can only be performed for the main arena.
         While mallopt calls malloc_consolidate to get rid of all fast
         bins (especially those larger than the new maximum) this does
         only happen for the main arena.  Trying to do this for any
         other arena would mean those arenas have to be locked and
         malloc_consolidate be called for them.  This is excessive.  And
         even if this is acceptable to somebody it still cannot solve
         the problem completely since if the arena is locked a
         concurrent malloc call might create a new arena which then
         could use the newly invalid fast bins.  */

      /* all bins past max_fast are empty 大于max_fast_bin部分都要为0*/
      if (av == &main_arena && i > max_fast_bin)
        assert (p == 0);

      while (p != 0)//fastbin链表中的所有chunk进行检测
        {
	  if (__glibc_unlikely (misaligned_chunk (p)))
	    malloc_printerr ("do_check_malloc_state(): "
			     "unaligned fastbin chunk detected");
          /* each chunk claims to be inuse */
          do_check_inuse_chunk (av, p);
          total += chunksize (p);
          /* chunk belongs in this bin */
          assert (fastbin_index (chunksize (p)) == i);
	  p = REVEAL_PTR (p->fd);
        }
    }

  /* check normal bins */
  for (i = 1; i < NBINS; ++i)
    {
      b = bin_at (av, i);

      /* binmap is accurate (except for bin 1 == unsorted_chunks) */
      //binmap准确除了bin1,此时检测对应的链表是否为空
      if (i >= 2)//非unsorted bin
        {
          unsigned int binbit = get_binmap (av, i);
          int empty = last (b) == b;
          if (!binbit)
            assert (empty);
          else if (!empty)
            assert (binbit);
        }

      for (p = last (b); p != b; p = p->bk)//遍历normal bin
        {
          /* each chunk claims to be free */
          do_check_free_chunk (av, p);//free chunk检测
          size = chunksize (p);
          total += size;
          if (i >= 2)//非unsorted bin
            {
              /* chunk belongs in bin */
              idx = bin_index (size);
              assert (idx == i);//index检测
              /* lists are sorted */
              assert (p->bk == b ||
                      (unsigned long) chunksize (p->bk) >= (unsigned long) chunksize (p));//是否严格保证头部方向size>=尾部方向size

              if (!in_smallbin_range (size))//large bin检测
                {
                  if (p->fd_nextsize != NULL)//关于fd/bk_nextsize的链表检测
                    {
                      if (p->fd_nextsize == p)
                        assert (p->bk_nextsize == p);
                      else
                        {
                          if (p->fd_nextsize == first (b))
                            assert (chunksize (p) < chunksize (p->fd_nextsize));
                          else
                            assert (chunksize (p) > chunksize (p->fd_nextsize));

                          if (p == first (b))
                            assert (chunksize (p) > chunksize (p->bk_nextsize));
                          else
                            assert (chunksize (p) < chunksize (p->bk_nextsize));
                        }
                    }
                  else
                    assert (p->bk_nextsize == NULL);//small bin中对应的nextsize必须为NULL ，因为不被使用
                }
            }
          else if (!in_smallbin_range (size))//unsorted bin & size属于large bin
            assert (p->fd_nextsize == NULL && p->bk_nextsize == NULL);//fd/bk nextsize链表为NULL 
          /* chunk is followed by a legal chain of inuse chunks 对chunk所在Inuse（地址上挨着的）链表进行检测*/
          for (q = next_chunk (p);
               (q != av->top && inuse (q) &&
                (unsigned long) (chunksize (q)) >= MINSIZE);
               q = next_chunk (q))
            do_check_inuse_chunk (av, q);
        }
    }

  /* top chunk is OK */
  check_chunk (av, av->top);//top chunk检测
}
#endif


/* ----------------- Support for debugging hooks -------------------- */
#if IS_IN (libc)
#include "hooks.c"
#endif


/* ----------- Routines dealing with system allocation -------------- */

/*
   sysmalloc handles malloc cases requiring more memory from the system.
   On entry, it is assumed that av->top does not have enough
   space to service request for nb bytes, thus requiring that av->top
   be extended or replaced.
 */

static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
  mchunkptr old_top;              /* incoming value of av->top */
  INTERNAL_SIZE_T old_size;       /* its size */
  char *old_end;                  /* its end address */

  long size;                      /* arg to first MORECORE or mmap call */
  char *brk;                      /* return value from MORECORE */

  long correction;                /* arg to 2nd MORECORE call */
  char *snd_brk;                  /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                    /* the allocated/returned chunk */
  mchunkptr remainder;            /* remainder from allocation */
  unsigned long remainder_size;   /* its size */


  size_t pagesize = GLRO (dl_pagesize);
  bool tried_mmap = false;


  /*
     If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
   */
  //1.在arena数量已满但是当前线程thread_arena还没创建过，那么arena_get会返回null，并传递到这
  //2.在arena数量未满但是地址空间不足以申请一个最小的heap(HEAP_MIN_SIZE)来创建arena，那么arena_get会返回null，并传递到这
  if (av == NULL
      || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)//3.av存在但是 nb字节书大于mmap_threshold且mmap region的数量没有达到最大值，尝试直接mmap映射
	  && (mp_.n_mmaps < mp_.n_mmaps_max)))//mmap_threshold 默认值：128K  最小值128k 最大值：32位512K  64位16\32M，通常32M
    {
      char *mm;           /* return value from mmap call*/

    try_mmap:
      /*
         Round up size to nearest page.  For mmapped chunks, the overhead
         is one SIZE_SZ unit larger than for normal chunks, because there
         is no following chunk whose prev_size field could be used.
        //要多申请一个SIZE_SZ ，用于表示下一个chunk的prev_size，因为req转换成nb（normal bytes）考虑了下一个chunk的prev_size
        //所以这里需要额外增加一个SIZE_SZ,以满足用户使用；但是mmap chunk并没有真的存在下一个chunk的prev_size，而是直接在chunk_size中包含了该余量（因对齐原因，实际会更多）
        //下面的misalign的作用是让用户使用的内存地址为MALLOC_ALIGNMENT对齐
        //因此存在misalign情况下布局为->
        //mmap_start|misalign|chunkheader|chunk payload|prev_size
        //
         See the front_misalign handling below, for glibc there is no
         need for further alignments unless we have have high alignment.
       */
      //MALLOC_ALIGNMENT 32:8 64:16
      //CHUNK_HDR_SZ 32:8  64:8/16 通常16
      if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)//对齐处理，nb会转换成页大小再进行映射
        size = ALIGN_UP (nb + SIZE_SZ, pagesize);//通常走这
      else
        size = ALIGN_UP (nb + SIZE_SZ + MALLOC_ALIGN_MASK, pagesize);
      tried_mmap = true;

      /* Don't try if size wraps around 0 */
      if ((unsigned long) (size) > (unsigned long) (nb))//如果size回滚到了0就不处理，否则，size>nb进行处理
        {
          mm = (char *) (MMAP (0, size,
			       mtag_mmap_flags | PROT_READ | PROT_WRITE, 0));//映射

          if (mm != MAP_FAILED)//没有失败的话
            {
              /*
                 The offset to the start of the mmapped region is stored
                 in the prev_size field of the chunk. This allows us to adjust
                 returned start address to meet alignment requirements here
                 and in memalign(), and still be able to compute proper
                 address argument for later munmap in free() and realloc().
               */

              if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)//MALLOC_ALIGNMENT一般为16  CHUNK_HDR_SZ可能为16（指针为8字节），也可能为8（指针为4字节）
                {
                  /* For glibc, chunk2mem increases the address by
                     CHUNK_HDR_SZ and MALLOC_ALIGN_MASK is
                     CHUNK_HDR_SZ-1.  Each mmap'ed area is page
                     aligned and therefore definitely
                     MALLOC_ALIGN_MASK-aligned.  */
                  assert (((INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK) == 0);//校验
                  front_misalign = 0;
                }
              else
                front_misalign = (INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK;//对齐处理，获取misalign    mm的起始地址必须MALLOC_ALIGNMENT对齐
              if (front_misalign > 0)
                {
                  correction = MALLOC_ALIGNMENT - front_misalign;//一般而言，这个值为8
                  p = (mchunkptr) (mm + correction);
		              set_prev_size (p, correction);//记录chunk之前的大小为8字节
                  set_head (p, (size - correction) | IS_MMAPPED);
                }
              else
                {
                  p = (mchunkptr) mm;
		              set_prev_size (p, 0);//设置之前的大小为0
                  set_head (p, size | IS_MMAPPED);//设置head is_mapped
                }

              /* update statistics */

              int new = atomic_exchange_and_add (&mp_.n_mmaps, 1) + 1;//原子加1,并得到旧值+1
              atomic_max (&mp_.max_n_mmaps, new);//更新历史使用最大数量mmap region

              unsigned long sum;
              sum = atomic_exchange_and_add (&mp_.mmapped_mem, size) + size;//原子更新glibc 管理的mmap的内存大小
              atomic_max (&mp_.max_mmapped_mem, sum);//更新历史最大使用的内存字节数

              check_chunk (av, p);//输入arena和其中的chunk p，检查属性;但是mmapchunk p本身是不太关注是主arena还是非主arena，默认下值A (NON_MAIN_ARENA)为0，表示为主分区，但是free时也不关注它，它只有在此处时，会稍微校验一下，但也是A标志无关

              return chunk2mem (p);//返回分配的内存
            }
        }
    }

  /* There are no usable arenas and mmap also failed.  */
  if (av == NULL)//av==NULL说明无可用arena且mmap失败，直接返回NULL
    return 0;

  /* Record incoming configuration of top */

  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));//记录之前的top信息

  brk = snd_brk = (char *) (MORECORE_FAILURE);//MORECORE（这个一般就是sbrk）失败的时候的返回值

  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert ((old_top == initial_top (av) && old_size == 0) ||//第一次使用的时候，old_size必须为0
          ((unsigned long) (old_size) >= MINSIZE &&//old_size必须>=MINSIZE
           prev_inuse (old_top) &&//top前一个chunk必须prev_inuse
           ((unsigned long) old_end & (pagesize - 1)) == 0));//top结尾必须页对齐

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));//假定了topchunk无法分配足够的内存，top要是能分裂的话，剩下的top必须>=MINSIZE


  if (av != &main_arena)//如果是非主分配区
    {
      heap_info *old_heap, *heap;
      size_t old_heap_size;

      /* First try to extend the current heap. */
      old_heap = heap_for_ptr (old_top);//通过HEAP_MAX_SIZE对齐得到top chunk 所在heap 的heap_info地址
      old_heap_size = old_heap->size;//获取top chunk 所在heap的size值，heap的可读写区域大熊啊
      if ((long) (MINSIZE + nb - old_size) > 0 //检测topchunk无法分配足够的内存
          && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)//扩容以增长topchunk
        {//如果heap扩容成功
          av->system_mem += old_heap->size - old_heap_size;//更新av中system_mem管理的内存值，包括所有heap可读写区域，Memory allocated from the system in this arena
          set_head (old_top, (((char *) old_heap + old_heap->size) - (char *) old_top)
                    | PREV_INUSE);//是则扩容后的heap的top chunk，且设置top chunk的前一个chunk的prev_inuse
        }
      else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad)))//扩容失败则新建new_heap,加上MINSIZE是为了让新的heap在分配内存以后能够还有MINSIZE留给新的top chunk
        {
          /* Use a newly allocated heap.  */
          heap->ar_ptr = av;//设置新的heap的ar_ptr
          heap->prev = old_heap;//设置前一个heap
          av->system_mem += heap->size;//设置av管理的内存大小统计量
          /* Set up the new top.  */
          top (av) = chunk_at_offset (heap, sizeof (*heap));//设置新的top   heap_for_ptr(top)对齐HEAP_MAX_SIZE就能得到所在的heap
          set_head (top (av), (heap->size - sizeof (*heap)) | PREV_INUSE);//设置top chunk（目前也是第一个chunk）的PREV_INUSE为1

          /* Setup fencepost and free the old top chunk with a multiple of
             MALLOC_ALIGNMENT in size. */
          /* The fencepost takes at least MINSIZE bytes, because it might
             become the top chunk again later.  Note that a footer is set
             up, too, although the chunk is marked in use. */
          old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;//可以看出包含fencepost的预留大小为>=MINSIZE且<2*MINSIZE
          set_head (chunk_at_offset (old_top, old_size + CHUNK_HDR_SZ),
		    0 | PREV_INUSE);//利用fencepost设置前一个chunk为PREV_INUSE,并且fencepost的大小为0
          if (old_size >= MINSIZE)//old top移出fencepost后，是否空间大于MINSIZE
            {              
              set_head (chunk_at_offset (old_top, old_size),
			CHUNK_HDR_SZ | PREV_INUSE);
              set_foot (chunk_at_offset (old_top, old_size), CHUNK_HDR_SZ);
              //  执行完上面一条语句后的布局
              //  布局 pos(old_top+old_size)| chunk head(mchunk_size=CHUNK_HDR_SZ|PREV_INUSE)-chunk head(mchunk_size=0|PREV_INUSE，mchunk_prev_size=CHUNK_HDR_SZ)  \
              //   设置新的old top的头信息，主要是为了之后将old heap的old top除去fencepost之外剩余部分进行free释放,而fencepost则保留足够的空间,未来可能再次成为top chunk
              set_head (old_top, old_size | PREV_INUSE | NON_MAIN_ARENA);
              _int_free (av, old_top, 1);//释放prev heap 的 剩余old top对应的chunk
            }
          else
            {
              set_head (old_top, (old_size + CHUNK_HDR_SZ) | PREV_INUSE);
              set_foot (old_top, (old_size + CHUNK_HDR_SZ));
              //   执行完上面两条语句后的布局
              //  布局  posold top chunk head(mchunk_size=oldsize+CHUNK_HDR_SZ|PREV_INUSE)-chunk head(mchunk_size=0|PREV_INUSE，mchunk_prev_size=oldsize+CHUNK_HDR_SZ)  \
              //  topchunk直接变成fencepost，不进行free操作释放chunk   
            }
        }
      else if (!tried_mmap)//变量默认为false，如果尝试过mmap则被设置为true;表明如果grow/new heap都失败，那就只能尝试一下mmap,这也是一种mmap条件
        /* We can at least try to use to mmap memory.  */
        goto try_mmap;
    }
  else     /* av == main_arena *//主分配区


    { /* Request enough space for nb + pad + overhead */
      size = nb + mp_.top_pad + MINSIZE;//1确保增长后分裂，topchunk还可以保留至少MINISIZE 的空间 2满足top_pad需求；

      /*
         If contiguous, we can subtract out existing space that we hope to
         combine with new space. We add it back later only if
         we don't actually get contiguous space.
       */
      //如果main_arena是连续的内存，计算除去已有的内存后还剩余的内存
      //当sbrk失败，通过补救措施mmap申请内存后，main_arena就不再是连续的arena了
      if (contiguous (av))
        size -= old_size;//通常假定了old top不够分配，所以size -old_size 一般而言是大于0的

      /*
         Round to a multiple of page size.
         If MORECORE is not contiguous, this ensures that we only call it
         with whole-page arguments.  And if MORECORE is contiguous and
         this is not first time through, this preserves page-alignment of
         previous calls. Otherwise, we correct to page-align below.
       */

      size = ALIGN_UP (size, pagesize);//向上对齐

      /*
         Don't try to call MORECORE if argument is so big as to appear
         negative. Note that since mmap takes size_t arg, it may succeed
         below even if we cannot call MORECORE.
       */

      if (size > 0)
        {
          brk = (char *) (MORECORE (size));//申请内存，一般情况下就是sbrk
          LIBC_PROBE (memory_sbrk_more, 2, brk, size);
        }

      if (brk == (char *) (MORECORE_FAILURE))
        {//主arena分配失败，利用mmap作为补救措施，注意：对于主分配区域we ignore mmap max count and threshold limits，但如果映射成功，主arena就设置成了非连续
          /*
             If have mmap, try using it as a backup when MORECORE fails or
             cannot be used. This is worth doing on systems that have "holes" in
             address space, so sbrk cannot extend to give contiguous space, but
             space is available elsewhere.  Note that we ignore mmap max count
             and threshold limits, since the space will not be used as a
             segregated mmap region.
           */

          /* Cannot merge with old top, so add its size back in */
          if (contiguous (av))
            size = ALIGN_UP (size + old_size, pagesize);//计算出一开始的size

          /* If we are relying on mmap as backup, then use larger units */
          //MMAP_AS_MORECORE_SIZE(1024*1024) is the minimum mmap size argument to use if   sbrk fails, and mmap is used as a backup
          if ((unsigned long) (size) < (unsigned long) (MMAP_AS_MORECORE_SIZE))
            size = MMAP_AS_MORECORE_SIZE;

          /* Don't try if size wraps around 0 *///如果回绕到0,应该是指溢出，不做mmap;否则，尝试mmap
          if ((unsigned long) (size) > (unsigned long) (nb))
            {
              char *mbrk = (char *) (MMAP (0, size,
					   mtag_mmap_flags | PROT_READ | PROT_WRITE,
					   0));

              if (mbrk != MAP_FAILED)//映射成功
                {
                  /* We do not need, and cannot use, another sbrk call to find end */
                  brk = mbrk;//brk设置为mmap地址
                  snd_brk = brk + size;//snd_brk为mmap地址使用size的尾部

                  /*
                     Record that we no longer have a contiguous sbrk region.
                     After the first time mmap is used as backup, we do not
                     ever rely on contiguous space since this could incorrectly
                     bridge regions.
                   */
                  set_noncontiguous (av);//设置arena为非连续区
                }
            }
        }

      if (brk != (char *) (MORECORE_FAILURE))//如果MORECORE成功了或者mmap成功了
        {
          if (mp_.sbrk_base == 0)// On  success,  sbrk()  returns  the  previous program break.
            mp_.sbrk_base = brk;//如果是第一次，则设置sbrk_base为sbrk的起始地址
          av->system_mem += size;//更新av 管理的内存

          /*
             If MORECORE extends previous space, we can likewise extend top size.
           */
          /*在malloc_init_state时，//初始化top值,av->top=&(av->top)最后的结果应该等同于这样,top->mchunk_size=last_remainder=0；
          所以如果是第一次分配成功时brk 和 old_end不相等，且old_size为0   这段仅仅是猜测；另外，外部如果直接并发调用了sbrk，也会造成这里地址不一样*/
          if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE))//这个if说明是通过sbrk分配的，和原来的topchunk连续，并且非mmap分配
            set_head (old_top, (size + old_size) | PREV_INUSE);//设置chunk

          else if (contiguous (av) && old_size && brk < old_end)//连续，old size存在  但是brk < old_end,校验错误
	    /* Oops!  Someone else killed our space..  Can't touch anything.  */
	    malloc_printerr ("break adjusted to free malloc space");

          /*
             Otherwise, make adjustments://作出调整

           * If the first time through or noncontiguous, we need to call sbrk
              just to find out where the end of memory lies.//第一次或非连续的情况下，需要通过调用sbrk知道最后的地址

           * We need to ensure that all returned chunks from malloc will meet
              MALLOC_ALIGNMENT  //返回的所有chunk都必须MALLOC_ALIGNMENT

           * If there was an intervening foreign sbrk, we need to adjust sbrk
              request size to account for fact that we will not be able to
              combine new space with existing space in old_top.
              //如果有外部的sbrk介入调用（具体哪使用暂不清楚，猜测可能是外部直接调系统调用sbrk），就会造成我们无法直接使用之前的old top，空间不连续
              //如果外部介入了，猜测释放的时候肯定不能直接sbrk(desc)，这样应该是会造成问题和错误,外部介入的sbrk应该是有限制的；

           * Almost all systems internally allocate whole pages at a time, in
              which case we might as well use the whole last page of request.//大多数系统系统内部会一次性分配整个页，在这种情况下，会使用请求页的剩余部分
              So we allocate enough more memory to hit a page boundary now,
              which in turn causes future contiguous calls to page-align.//强调了页对齐
           */

          else//非连续/第一次分配old_size为0/brk>old_end中间存在外部sbrk调用    进入这条分支的情况通常不多，但却很麻烦，不花太多精力
            {
              front_misalign = 0;
              end_misalign = 0;
              correction = 0;
              aligned_brk = brk;

              /* handle contiguous cases */
              if (contiguous (av))//连续标志存在；但新分配的内存地址大于原来的top chunk的结束地址，不连续（比如其它线程外部主动调用了sbrk，即使arena已经锁住了）
                {
                  /* Count foreign sbrk as system_mem.  */
                  if (old_size)//为0说明是第一次分配；否则表示将外部介入的sbrk分配的内存一并计入到该分配区分配的内存大小
                    av->system_mem += brk - old_end;

                  /* Guarantee alignment of first new chunk made from this space */

                  front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                  if (front_misalign > 0)//保证chunk对齐
                    {
                      /*
                         Skip over some bytes to arrive at an aligned position.
                         We don't need to specially mark these wasted front bytes.//会浪费一些top前端的字节,它们永远不会被访问
                         They will never be accessed anyway because
                         prev_inuse of av->top (and any chunk created from its start)
                         is always true after initialization.
                       */

                      correction = MALLOC_ALIGNMENT - front_misalign;//correction：纠正，用于处理外部sbrk介入和对齐的情形
                      aligned_brk += correction;//aligned_brk对齐后的brk
                    }

                  /*
                     If this isn't adjacent to existing space, then we will not
                     be able to merge with old_top space, so must add to 2nd request.
                   */

                  correction += old_size;//外部sbrk介入（造成一开始的oldsize被别处使用），无法和之前的空间地址直接连续在一起，所以这里加上补偿的空间大小

                  /* Extend the end address to hit a page boundary */
                  end_misalign = (INTERNAL_SIZE_T) (brk + size + correction);//brk是开始地址，size是额外申请的大小，correction是纠错大小
                  correction += (ALIGN_UP (end_misalign, pagesize)) - end_misalign;//纠错大小再加上尾部页对齐需要的额外空间

                  assert (correction >= 0);
                  snd_brk = (char *) (MORECORE (correction));//second sbrk，利用correction进行修正（brk开始已经个有了额外的size大小）

                  /*
                     If can't allocate correction, try to at least find out current
                     brk.  It might be enough to proceed without failing.

                     Note that if second sbrk did NOT fail, we assume that space
                     is contiguous with first sbrk. This is a safe assumption unless
                     program is multithreaded but doesn't use locks and a foreign sbrk
                     occurred between our first and second calls.//这里安全的假设是第一次和第二次调用之间没有外部介入的sbrk或者多线程中没有使用锁访问（猜测没有用锁可能在程序bug或则用户手动修改源码时发生吧）
                   */

                  if (snd_brk == (char *) (MORECORE_FAILURE))//如果弥补失败，则放弃，让correction为0,snd_brk为最新的program break地址(就是最高brk地址)
                    {
                      correction = 0;
                      snd_brk = (char *) (MORECORE (0));
                    }
                }

              /* handle non-contiguous cases */
              else//非连续；主分区brk不足而第一次mmap后就变成了非连续，虽然是非连续，但进入该函数的时候，除了mmap ，brk也还是有机会进入这里
                {
                  if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)//像是64位处理（MALLOC_ALIGNMENT:16   CHUNK_HDR_SZ两个8字节指针）
                    /* MORECORE/mmap must correctly align */
                    assert (((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0);
                  else
                    {//像是32位处理
                      front_misalign = (INTERNAL_SIZE_T) chunk2mem (brk) & MALLOC_ALIGN_MASK;
                      if (front_misalign > 0)
                        {
                          /*
                             Skip over some bytes to arrive at an aligned position.
                             We don't need to specially mark these wasted front bytes.
                             They will never be accessed anyway because
                             prev_inuse of av->top (and any chunk created from its start)
                             is always true after initialization.
                           */

                          aligned_brk += MALLOC_ALIGNMENT - front_misalign;//为了对齐，记录需要的对齐量
                        }
                    }

                  /* Find out current end of memory */
                  if (snd_brk == (char *) (MORECORE_FAILURE))//如果不是mmap的话
                    {
                      snd_brk = (char *) (MORECORE (0));//将新的分配地址放到snd_brk中
                    }
                }

              /* Adjust top based on results of second sbrk */
              if (snd_brk != (char *) (MORECORE_FAILURE))//分配成功
                {
                  av->top = (mchunkptr) aligned_brk;//将top设置为aligned_brk；这里可以看出来 top chunk 既可以出现在program break heap区域，也可以出现在mmap区域
                  set_head (av->top, (snd_brk - aligned_brk + correction) | PREV_INUSE);//设置top chunk属性
                  av->system_mem += correction;//更新system_mem属性

                  /*
                     If not the first time through, we either have a
                     gap due to foreign sbrk or a non-contiguous region.  Insert a
                     double fencepost at old_top to prevent consolidation with space
                     we don't own. These fenceposts are artificial chunks that are
                     marked as inuse and are in any case too small to use.  We need
                     two to make sizes and alignments work out.
                   */

                  if (old_size != 0)//如果不是第一次的话，这个值不为0
                    {
                      /*
                         Shrink old_top to insert fenceposts, keeping size a
                         multiple of MALLOC_ALIGNMENT. We know there is at least
                         enough space in old_top to do this.
                       */
                      //因为新的brk地址和原先的top在地址上不连续，这里需要在原先的top中插入一个fencepost,虽然它不再回收使用了
                      //空间肯定足够，因为topchunk至少包含一个MINSIZE
                      old_size = (old_size - 2 * CHUNK_HDR_SZ) & ~MALLOC_ALIGN_MASK;
                      set_head (old_top, old_size | PREV_INUSE);

                      /*
                         Note that the following assignments completely overwrite
                         old_top when old_size was previously MINSIZE.  This is
                         intentional. We need the fencepost, even if old_top otherwise gets
                         lost.
                       */
		      set_head (chunk_at_offset (old_top, old_size),CHUNK_HDR_SZ | PREV_INUSE);
		      set_head (chunk_at_offset (old_top, old_size + CHUNK_HDR_SZ),		CHUNK_HDR_SZ | PREV_INUSE);//类似前面的fencpost的布局，又最后的地方又略微有点点区别

                      /* If possible, release the rest. */
                      if (old_size >= MINSIZE)//如果old top剩余空间大于MINSIZE，则将该部分内存进行释放
                        {
                          _int_free (av, old_top, 1);
                        }
                    }
                }
            }
        }
    } /* if (av !=  &main_arena) */

  if ((unsigned long) av->system_mem > (unsigned long) (av->max_system_mem))
    av->max_system_mem = av->system_mem;//像是更新历史使用最大的内存
  check_malloc_state (av);//检测

  /* finally, do the allocation */
  p = av->top;
  size = chunksize (p);

  /* check that one of the above allocation paths succeeded */
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))//上面top扩展成功，这个时候从top进行分配
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (p, nb);
      av->top = remainder;//此时topchunk等同remainder
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p);
    }

  /* catch all failure paths */
  __set_errno (ENOMEM);
  return 0;
}


/*
   systrim is an inverse of sorts to sysmalloc.  It gives memory back
   to the system (via negative arguments to sbrk) if there is unused
   memory at the `high' end of the malloc pool. It is called
   automatically by free() when top space exceeds the trim
   threshold. It is also called by the public malloc_trim routine.  It
   returns 1 if it actually released any memory, else 0.
 */

static int
systrim (size_t pad, mstate av)//收缩topchunk，归还内存给系统；简单来说就是依据topchunksize向下页对齐的值为缩小量对topchunk进行缩减；只适用main_arena
{
  long top_size;         /* Amount of top-most memory */
  long extra;            /* Amount to release */
  long released;         /* Amount actually released */
  char *current_brk;     /* address returned by pre-check sbrk call */
  char *new_brk;         /* address returned by post-check sbrk call */
  size_t pagesize;
  long top_area;

  pagesize = GLRO (dl_pagesize);
  top_size = chunksize (av->top);

  top_area = top_size - MINSIZE - 1;
  if (top_area <= pad)//这里限制top_area 至少要有 pad空间(默认0)才能进一步处理(等同于topsize>MINSIZE+1+pad(0))，否则返回；
    return 0;

  /* Release in pagesize units and round down to the nearest page.  */
  extra = ALIGN_DOWN(top_area - pad, pagesize);//top_area-pad后向下页对齐，得到要释放的字节数

  if (extra == 0)//为0说明不需要释放
    return 0;

  /*
     Only proceed if end of memory is where we last set it.
     This avoids problems if there were foreign sbrk calls.
   */
  current_brk = (char *) (MORECORE (0));//获取当前brk位置
  if (current_brk == (char *) (av->top) + top_size)//current_brk和top chunk末尾地址一致;目前看这种方式只适合main_arena;
    {
      /*
         Attempt to release memory. We ignore MORECORE return value,
         and instead call again to find out where new end of memory is.
         This avoids problems if first call releases less than we asked,
         of if failure somehow altered brk value. (We could still
         encounter problems if it altered brk in some very bad way,
         but the only thing we can do is adjust anyway, which will cause
         some downstream failure.)
       */

      MORECORE (-extra);//收缩
      new_brk = (char *) (MORECORE (0));//新的brk

      LIBC_PROBE (memory_sbrk_less, 2, new_brk, extra);

      if (new_brk != (char *) MORECORE_FAILURE)
        {//收缩成功
          released = (long) (current_brk - new_brk);//收缩大小

          if (released != 0)
            {
              /* Success. Adjust top. */
              av->system_mem -= released;//修改记录申请的系统内存大小
              set_head (av->top, (top_size - released) | PREV_INUSE);//修改topchunk大小
              check_malloc_state (av);//一堆检测
              return 1;
            }
        }
    }
  return 0;
}

static void
munmap_chunk (mchunkptr p)//这里只有mmap的区域才会进入，mmap时一般只有一个chunk在使用,且这个chunk会进行对齐，有可能最前面有一小段空间不会被使用
{//可以对应sysmalloc查看申请过程
  size_t pagesize = GLRO (dl_pagesize);//页大小
  INTERNAL_SIZE_T size = chunksize (p);//chunk大小

  assert (chunk_is_mmapped (p));

  uintptr_t mem = (uintptr_t) chunk2mem (p);
  uintptr_t block = (uintptr_t) p - prev_size (p);
  size_t total_size = prev_size (p) + size;//这种操作表明mmap方式得到的chunk之前还有一块内存，这部分内存（暂不清楚作用,可能是对齐留下的）的大小记录在prev_size(p)中
  /* Unfortunately we have to do the compilers job by hand here.  Normally
     we would test BLOCK and TOTAL-SIZE separately for compliance with the
     page size.  But gcc does not recognize the optimization possibility
     (in the moment at least) so we combine the two values into one before
     the bit test.  */
  if (__glibc_unlikely ((block | total_size) & (pagesize - 1)) != 0//block total_size都必须页对齐
      || __glibc_unlikely (!powerof2 (mem & (pagesize - 1))))//检测mem的页内偏移地址必须是2的指数次幂
    malloc_printerr ("munmap_chunk(): invalid pointer");

  atomic_decrement (&mp_.n_mmaps);//减少nmap数量
  atomic_add (&mp_.mmapped_mem, -total_size);//减少申请的mmaped_mem

  /* If munmap failed the process virtual memory address space is in a
     bad shape.  Just leave the block hanging around, the process will
     terminate shortly anyway since not much can be done.  */
  __munmap ((char *) block, total_size);//Deallocate any mapping for the region starting at ADDR and extending LEN  bytes.
}

#if HAVE_MREMAP

static mchunkptr
mremap_chunk (mchunkptr p, size_t new_size)
{
  size_t pagesize = GLRO (dl_pagesize);
  INTERNAL_SIZE_T offset = prev_size (p);
  INTERNAL_SIZE_T size = chunksize (p);
  char *cp;

  assert (chunk_is_mmapped (p));

  uintptr_t block = (uintptr_t) p - offset;
  uintptr_t mem = (uintptr_t) chunk2mem(p);
  size_t total_size = offset + size;
  if (__glibc_unlikely ((block | total_size) & (pagesize - 1)) != 0
      || __glibc_unlikely (!powerof2 (mem & (pagesize - 1))))
    malloc_printerr("mremap_chunk(): invalid pointer");

  /* Note the extra SIZE_SZ overhead as in mmap_chunk(). */
  new_size = ALIGN_UP (new_size + offset + SIZE_SZ, pagesize);

  /* No need to remap if the number of pages does not change.  */
  if (total_size == new_size)//大小一致直接返回，无需remap
    return p;
//MREMAP_MAYMOVE:
// By default, if there is not sufficient space to expand a mapping at its current location, then mremap()
// fails.  If this flag is specified, then the kernel is permitted to relocate the mapping to a  new  vir‐
// tual  address,  if necessary.  If the mapping is relocated, then absolute pointers into the old mapping
// location become invalid (offsets relative to the starting address of the mapping should be employed).
  cp = (char *) __mremap ((char *) block, total_size, new_size,
                          MREMAP_MAYMOVE);

  if (cp == MAP_FAILED)
    return 0;

  p = (mchunkptr) (cp + offset);

  assert (aligned_OK (chunk2mem (p)));

  assert (prev_size (p) == offset);
  set_head (p, (new_size - offset) | IS_MMAPPED);

  INTERNAL_SIZE_T new;
  new = atomic_exchange_and_add (&mp_.mmapped_mem, new_size - size - offset)//这个原子操作直接更新了mmapped_mem，但返回的旧值+change值用于后续更新max_mmapped_mem
        + new_size - size - offset;
  atomic_max (&mp_.max_mmapped_mem, new);//如果new更大则更新max_mmapped_mem
  return p;
}
#endif /* HAVE_MREMAP */

/*------------------------ Public wrappers. --------------------------------*/

#if USE_TCACHE

/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;//这里对应chunk的fd
  /* This field exists to detect double frees.  */
  uintptr_t key;//对应bk，检测free两次异常，在链表中时是tcache_key，不在链表时被设置为0
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread bool tcache_shutting_down = false;
static __thread tcache_perthread_struct *tcache = NULL;

/* Process-wide key to try and catch a double-free in the same thread.  */
static uintptr_t tcache_key;//进程级别的key，用来尝试和捕获double free操作

/* The value of tcache_key does not really have to be a cryptographically
   secure random number.  It only needs to be arbitrary enough so that it does
   not collide with values present in applications.  If a collision does happen
   consistently enough, it could cause a degradation in performance since the
   entire list is checked to check if the block indeed has been freed the
   second time.  The odds of this happening are exceedingly low though, about 1
   in 2^wordsize.  There is probably a higher chance of the performance
   degradation being due to a double free where the first free happened in a
   different thread; that's a case this check does not cover.  */
static void
tcache_key_initialize (void)
{
  if (__getrandom (&tcache_key, sizeof(tcache_key), GRND_NONBLOCK)
      != sizeof (tcache_key))
    {
      tcache_key = random_bits ();
#if __WORDSIZE == 64
      tcache_key = (tcache_key << 32) | random_bits ();
#endif
    }
}

/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)//结合tcache_get可以发现，tcache时单链表（利用fd）,后入先出
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);//说明cache->entries中放的都是mem而不是chunk，next都是指向的mem(实际就是chunk的fd)

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache_key;
  //利用位置信息对指针信息进行保护
  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];//取出第一个tcache chunk
  if (__glibc_unlikely (!aligned_OK (e)))//取出的chunk地址必须MALLOC_ALIGNMENT对齐，后12位为原始地址，因此可以这样检测
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);//揭示下一个出链表的真实指针地址并放入链表头；链表头是没有加密的
  --(tcache->counts[tc_idx]);//减少计数
  e->key = 0;//将bk置零，用于检测free double异常
  return (void *) e;//这个e对应的就是chunk的mem
}

static void
tcache_thread_shutdown (void)
{
  int i;
  tcache_perthread_struct *tcache_tmp = tcache;

  tcache_shutting_down = true;

  if (!tcache)
    return;

  /* Disable the tcache and prevent it from being reinitialized.  */
  tcache = NULL;

  /* Free all of the entries and the tcache itself back to the arena
     heap for coalescing.  */
  for (i = 0; i < TCACHE_MAX_BINS; ++i)
    {
      while (tcache_tmp->entries[i])
	{
	  tcache_entry *e = tcache_tmp->entries[i];
	  if (__glibc_unlikely (!aligned_OK (e)))
	    malloc_printerr ("tcache_thread_shutdown(): "
			     "unaligned tcache chunk detected");
	  tcache_tmp->entries[i] = REVEAL_PTR (e->next);
	}
	  __libc_free (e);
    }

  __libc_free (tcache_tmp);
}

static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;
  //acquires an arena and locks the corresponding mutex.
  //先尝试获取thread_arena，不行就的话且narenas_limit没达到上限则申请一个新的arena,否则reused_arena利用现有的arena
  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);//尝试通过ar_ptr获取请求为bytes字节的内存
  if (!victim && ar_ptr != NULL)
    {
      /* If we don't have the main arena, then maybe the failure is due to running   out of mmapped areas, so we can try allocating on the main arena.
   Otherwise, it is likely that sbrk() has failed and there is still a chance  to mmap(), so try one of the other arenas.  对一些特殊的失败情况尝试补救处理*/
      //arena_get (ar_ptr, bytes); victim = _int_malloc (ar_ptr, bytes);初次申请失败时进行如下补救
    //基本等同于如果入参ar_ptr不是main_arena，则返回main_arena;
    //否则，arena_get2的avoid_arena=main_arena来获取一个arena
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }


  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;//初始化tcache
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}
//每个线程在第一次malloc时，会初始化tcahce，此后tcahce不再为null，但还没有存在任何真正的tcache chunk
//free非mmap chunk时，也会进行调用
# define MAYBE_INIT_TCACHE() \
  if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();//通过arean_get/_int_malloc申请tcache_perthread_struct结构体，初始化为0并赋值tcache

#else  /* !USE_TCACHE */
# define MAYBE_INIT_TCACHE()

static void
tcache_thread_shutdown (void)
{
  /* Nothing to do if there is no thread cache.  */
}

#endif /* !USE_TCACHE  */

#if IS_IN (libc)
void *
__libc_malloc (size_t bytes)
{
  //typedef struct malloc_state *mstate; 定义arean指针
  mstate ar_ptr;
  void *victim;

  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,
                  "PTRDIFF_MAX is not more than half of SIZE_MAX");
  //是否初始化；第一次会进入,主要初始化main_arena，并设置一些全局配置变量
  if (!__malloc_initialized)
    ptmalloc_init ();
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes))//将bytes转换成有效的chunk大小并存到tbytes
    {
      __set_errno (ENOMEM);
      return NULL;
    }
    //chunksize to  tcache index
  size_t tc_idx = csize2tidx (tbytes);
  //如果使用了TCACHE机制，并且tcache为NULL ，则调用tcache_init;
  //static __thread tcache_perthread_struct *tcache = NULL; __thread是gcc线程局部存储，每个线程有独立的该变量互不影响，也即每个线程有自己的tcache chunk
  //tcache_perthread_struct是tcahce的存储结构;如果tchace为NULL ,就进行初始化；
  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;//和gcc编译相关
  //malloc时，最开始先尝试从tcache中获取
  if (tc_idx < mp_.tcache_bins//申请大小这个判断确定是否落在tcache范围
      && tcache//tcache存在
      && tcache->counts[tc_idx] > 0)//对应的链表存在可用tcache chunk
    {
      victim = tcache_get (tc_idx);//直接从tcache中获取并返回
      return tag_new_usable (victim);//此方法和mtag/arm有关，除去这部分后相当于直接返回参数指针
    }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)//使用单线程应该会走这进行分配
    {//在没有启用mtag时，tag_new_usable直接返回输入值
    //由于是单线程，所以只需要使用main_arean，没有arena竞争
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }   
  //多线程环境下，需要先获取arena并加锁
  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);//常规分配过程，先从fastbin开始
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      /* If we don't have the main arena, then maybe the failure is due to running  out of mmapped areas, so we can try allocating on the main arena.
   Otherwise, it is likely that sbrk() has failed and there is still a chance   to mmap(), so try one of the other arenas.
   mmaped area即vma数量大于允许数造成的分配失败，则考虑从main arean分配
   如果是sbrk造成的分配失败（main arena失败），则尝试找一个其它的arena
     */
      ar_ptr = arena_get_retry (ar_ptr, bytes);//必要的时候会更新thread_arena为新的arean  (static __thread mstate thread_arena,这个变量也是一个线程一个 )
    }
      victim = _int_malloc (ar_ptr, bytes);

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  victim = tag_new_usable (victim);//不使用mtag因此直接返回自己

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)

void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */
  //free NULL 直接返回
  if (mem == 0)                              /* free(0) has no effect */
    return;

  /* Quickly check that the freed pointer matches the tag for the memory.
     This gives a useful double-free detection.  */
  if (__glibc_unlikely (mtag_enabled))//如果激活了mtag,和arm相关，暂不管
    *(volatile char *)mem;//感觉这里是进行了一次内存访问，如果非法地址就会访问失败？

  int err = errno;//记录一开始的errno

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* See if the dynamic brk/mmap threshold needs adjusting.
	 Dumped fake mmapped chunks do not affect the threshold.  */
      if (!mp_.no_dyn_threshold//默认mmap_threshold是动态的，除非用户手动设置非动态;mmap_threshold默认值是DEFAULT_MMAP_THRESHOLD，为128K
          && chunksize_nomask (p) > mp_.mmap_threshold  //p的chunksize大于动态的mmap_threshold 且小于默认的DEFAULT_MMAP_THRESHOLD_MAX（32:512K/64:16\32M）
          && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);//利用p的chunksize更新mmap_threshold，该阈值只增不降，默认(32/64位)128K,32位最大512K,64位最大16\32M
          //trim_threshold影响systrim,说明mmap chunk释放的越大，说明大内存越多，越不需要进行收缩，该阈值只增长不降
          mp_.trim_threshold = 2 * mp_.mmap_threshold;//更新trim_threshold收缩阈值，为2倍mmap_threshold即默认(32/64位)256K，32位最大1M,64位最大32\64M
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
    }
  else
    {
      MAYBE_INIT_TCACHE ();//tcache为NULL 则初始化

      /* Mark the chunk as belonging to the library again.  */
      (void)tag_region (chunk2mem (p), memsize (p));//如果没有启用mtag，则相当于什么也没做；和arm架构相关，暂不管

      ar_ptr = arena_for_chunk (p);//没有对arena加锁
      _int_free (ar_ptr, p, 0);
    }

  __set_errno (err);//上面正常返回，则还原记录的err
}
libc_hidden_def (__libc_free)

void *
__libc_realloc (void *oldmem, size_t bytes)
{
  mstate ar_ptr;
  INTERNAL_SIZE_T nb;         /* padded request size */

  void *newp;             /* chunk to return */
  //是否初始化；第一次会进入,主要初始化main_arena，并设置一些全局配置变量
  if (!__malloc_initialized)
    ptmalloc_init ();

#if REALLOC_ZERO_BYTES_FREES
  if (bytes == 0 && oldmem != NULL)//如果申请字节为0，oldmem不为NULL，则相当于free oldmem释放内存
    {
      __libc_free (oldmem); return 0;
    }
#endif

  /* realloc of null is supposed to be same as malloc */
  if (oldmem == 0)//如果oldmem为NULL，则相当于直接malloc bytes内存
    return __libc_malloc (bytes);

  /* Perform a quick check to ensure that the pointer's tag matches the
     memory's tag.  */
  if (__glibc_unlikely (mtag_enabled))//arm相关，暂不管
    *(volatile char*) oldmem;

  /* chunk corresponding to oldmem */
  const mchunkptr oldp = mem2chunk (oldmem);
  /* its size */
  const INTERNAL_SIZE_T oldsize = chunksize (oldp);
  //依据chunk性质设置ar_ptr
  if (chunk_is_mmapped (oldp))
    ar_ptr = NULL;
  else
    {
      MAYBE_INIT_TCACHE ();
      ar_ptr = arena_for_chunk (oldp);//以不加锁的形式获取arena
    }

  /* Little security check which won't hurt performance: the allocator
     never wrapps around at the end of the address space.  Therefore
     we can exclude some size values which might appear here by
     accident or by "design" from some intruder.  */
  if ((__builtin_expect ((uintptr_t) oldp > (uintptr_t) -oldsize, 0)//32/64位uintptr_t不一样；这里的作用是地址溢出检测
       || __builtin_expect (misaligned_chunk (oldp), 0)))//对齐检测
      malloc_printerr ("realloc(): invalid pointer");

  if (!checked_request2size (bytes, &nb))//nb转换成能容纳bytes的最小chunk
    {
      __set_errno (ENOMEM);
      return NULL;
    }

  if (chunk_is_mmapped (oldp))
    {
      void *newmem;

#if HAVE_MREMAP  //用于判定是否使用mremap来重新分配内存，如果能remap则remap，默认为0即不允许mremap
      newp = mremap_chunk (oldp, nb);
      if (newp)
	{
	  void *newmem = chunk2mem_tag (newp);//arm相关，但此处相当于直接返回newp的mem
	  /* Give the new block a different tag.  This helps to ensure
	     that stale handles to the previous mapping are not
	     reused.  There's a performance hit for both us and the
	     caller for doing this, so we might want to
	     reconsider.  */
	  return tag_new_usable (newmem);//arm相关，相当于直接返回newmem
	}
#endif
      /* Note the extra SIZE_SZ overhead. */
      //此处的SIZE_SZ原因可以参考sysmalloc中try_mmap区域注释：要多申请一个SIZE_SZ ，用于表示下一个chunk的prev_size，因为req转换成nb（normal bytes）考虑了下一个chunk的prev_size；
      //但是mmap chunk并没有真的存在下一个chunk的prev_size，而是直接在chunk_size中包含了该余量（因对齐原因，实际会更多）
      //所以这个地方减去SIZE_SZ再判断
      //最终效果是，如果没有启用mremap机制，且oldchunk能够容纳申请的内存，那么什么也不做，直接利用oldchunk
      if (oldsize - SIZE_SZ >= nb)
        return oldmem;                         /* do nothing */

      //到此处，说明oldchunk无法容纳新申请的内存，那么执行申请/拷贝/释放达到目标效果
      /* Must alloc, copy, free. */
      newmem = __libc_malloc (bytes);
      if (newmem == 0)
        return 0;              /* propagate failure */

      memcpy (newmem, oldmem, oldsize - CHUNK_HDR_SZ);
      munmap_chunk (oldp);
      return newmem;
    }
  //非mmapchunk情形处理
  if (SINGLE_THREAD_P)//单线程_int_realloc
    {
      newp = _int_realloc (ar_ptr, oldp, oldsize, nb);
      assert (!newp || chunk_is_mmapped (mem2chunk (newp)) ||
	      ar_ptr == arena_for_chunk (mem2chunk (newp)));

      return newp;
    }

  __libc_lock_lock (ar_ptr->mutex);
  //多线程的_int_realloc
  newp = _int_realloc (ar_ptr, oldp, oldsize, nb);

  __libc_lock_unlock (ar_ptr->mutex);
  assert (!newp || chunk_is_mmapped (mem2chunk (newp)) ||
          ar_ptr == arena_for_chunk (mem2chunk (newp)));

  if (newp == NULL)
    {
      /* Try harder to allocate memory in other arenas.  */
      LIBC_PROBE (memory_realloc_retry, 2, bytes, oldmem);
      newp = __libc_malloc (bytes);//通过libc_malloc再尝试分配，成功的话接着则拷贝copy与释放free;__libc_malloc相比_int_malloc，前者可能会发生切换arena，后者不会
      if (newp != NULL)
        {
	  size_t sz = memsize (oldp);
	  memcpy (newp, oldmem, sz);
	  (void) tag_region (chunk2mem (oldp), sz);
          _int_free (ar_ptr, oldp, 0);
        }
    }

  return newp;
}
libc_hidden_def (__libc_realloc)

void *
__libc_memalign (size_t alignment, size_t bytes)
{
  if (!__malloc_initialized)
    ptmalloc_init ();

  void *address = RETURN_ADDRESS (0);
  return _mid_memalign (alignment, bytes, address);
}

static void *
_mid_memalign (size_t alignment, size_t bytes, void *address)
{
  mstate ar_ptr;
  void *p;

  /* If we need less alignment than we give anyway, just relay to malloc.  */
  if (alignment <= MALLOC_ALIGNMENT)
    return __libc_malloc (bytes);

  /* Otherwise, ensure that it is at least a minimum chunk size */
  if (alignment < MINSIZE)
    alignment = MINSIZE;

  /* If the alignment is greater than SIZE_MAX / 2 + 1 it cannot be a
     power of 2 and will cause overflow in the check below.  */
  if (alignment > SIZE_MAX / 2 + 1)
    {
      __set_errno (EINVAL);
      return 0;
    }


  /* Make sure alignment is power of 2.  */
  if (!powerof2 (alignment))
    {
      size_t a = MALLOC_ALIGNMENT * 2;
      while (a < alignment)
        a <<= 1;
      alignment = a;
    }

  if (SINGLE_THREAD_P)
    {
      p = _int_memalign (&main_arena, alignment, bytes);
      assert (!p || chunk_is_mmapped (mem2chunk (p)) ||
	      &main_arena == arena_for_chunk (mem2chunk (p)));
      return tag_new_usable (p);
    }

  arena_get (ar_ptr, bytes + alignment + MINSIZE);

  p = _int_memalign (ar_ptr, alignment, bytes);
  if (!p && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_memalign_retry, 2, bytes, alignment);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      p = _int_memalign (ar_ptr, alignment, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  assert (!p || chunk_is_mmapped (mem2chunk (p)) ||
          ar_ptr == arena_for_chunk (mem2chunk (p)));
  return tag_new_usable (p);
}
/* For ISO C11.  */
weak_alias (__libc_memalign, aligned_alloc)
libc_hidden_def (__libc_memalign)

void *
__libc_valloc (size_t bytes)
{
  if (!__malloc_initialized)
    ptmalloc_init ();

  void *address = RETURN_ADDRESS (0);
  size_t pagesize = GLRO (dl_pagesize);
  return _mid_memalign (pagesize, bytes, address);
}

void *
__libc_pvalloc (size_t bytes)
{
  if (!__malloc_initialized)
    ptmalloc_init ();

  void *address = RETURN_ADDRESS (0);
  size_t pagesize = GLRO (dl_pagesize);
  size_t rounded_bytes;
  /* ALIGN_UP with overflow check.  */
  if (__glibc_unlikely (__builtin_add_overflow (bytes,
						pagesize - 1,
						&rounded_bytes)))
    {
      __set_errno (ENOMEM);
      return 0;
    }
  rounded_bytes = rounded_bytes & -(pagesize - 1);

  return _mid_memalign (pagesize, rounded_bytes, address);
}

void *
__libc_calloc (size_t n, size_t elem_size)//The memory is set to zero.
{
  mstate av;
  mchunkptr oldtop;
  INTERNAL_SIZE_T sz, oldtopsize;
  void *mem;
  unsigned long clearsize;
  unsigned long nclears;
  INTERNAL_SIZE_T *d;
  ptrdiff_t bytes;
//n*elem_size 结果 强制转换存放再bytes;如果没有溢出返回false，溢出的话返回true
  if (__glibc_unlikely (__builtin_mul_overflow (n, elem_size, &bytes)))//溢出检查，不允许溢出
    {
       __set_errno (ENOMEM);
       return NULL;
    }

  sz = bytes;
//是否初始化；第一次会进入,主要初始化main_arena，并设置一些全局配置变量
  if (!__malloc_initialized)
    ptmalloc_init ();

  MAYBE_INIT_TCACHE ();

  if (SINGLE_THREAD_P)
    av = &main_arena;
  else
    arena_get (av, sz);

  if (av)
    {
      /* Check if we hand out the top chunk, in which case there may be no
	 need to clear. */
#if MORECORE_CLEARS//默认为1
      oldtop = top (av);
      oldtopsize = chunksize (top (av));
# if MORECORE_CLEARS < 2
      /* Only newly allocated memory is guaranteed to be cleared.  */
      //用历史最大管理的内存更新oldtopsize;个人理解是只有新申请的sbrk才被初始化，已经申请过的不会清0；
      //heap是匿名vma_area区域，所以第一次会清0，但是已经映射的部分不会再清0，所以后面要手动清0
      if (av == &main_arena &&
	  oldtopsize < mp_.sbrk_base + av->max_system_mem - (char *) oldtop)
	oldtopsize = (mp_.sbrk_base + av->max_system_mem - (char *) oldtop);
# endif
      if (av != &main_arena)
	{
	  heap_info *heap = heap_for_ptr (oldtop);
	  if (oldtopsize < (char *) heap + heap->mprotect_size - (char *) oldtop)
	    oldtopsize = (char *) heap + heap->mprotect_size - (char *) oldtop;
	}
#endif
    }
  else
    {
      /* No usable arenas.  */
      oldtop = 0;
      oldtopsize = 0;
    }
  mem = _int_malloc (av, sz);

  assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
          av == arena_for_chunk (mem2chunk (mem)));

  if (!SINGLE_THREAD_P)//多线程环境
    {
      if (mem == 0 && av != NULL)//如果没有申请到，那么就尝试换arena申请
	{
	  LIBC_PROBE (memory_calloc_retry, 1, sz);
	  av = arena_get_retry (av, sz);
	  mem = _int_malloc (av, sz);
	}

      if (av != NULL)
	__libc_lock_unlock (av->mutex);
    }

  /* Allocation failed even after a retry.  */
  if (mem == 0)//没申请到就结束
    return 0;

  mchunkptr p = mem2chunk (mem);

  /* If we are using memory tagging, then we need to set the tags
     regardless of MORECORE_CLEARS, so we zero the whole block while
     doing so.  */
  if (__glibc_unlikely (mtag_enabled))//arm相关，暂不管
    return tag_new_zero_region (mem, memsize (p));//清0

  INTERNAL_SIZE_T csz = chunksize (p);//新申请的区域

  /* Two optional cases in which clearing not necessary */
  if (chunk_is_mmapped (p))
    {
      if (__builtin_expect (perturb_byte, 0))//默认为0，不执行清空；实际上mmap区域默认匿名映射必定内容为0
        return memset (mem, 0, sz);

      return mem;
    }

#if MORECORE_CLEARS
  if (perturb_byte == 0 && (p == oldtop && csz > oldtopsize))
    {
      /* clear only the bytes from non-freshly-sbrked memory */
      csz = oldtopsize;
    }
#endif

  /* Unroll clear of <= 36 bytes (72 if 8byte sizes).  We know that
     contents have an odd number of INTERNAL_SIZE_T-sized words;
     minimally 3.  */
  d = (INTERNAL_SIZE_T *) mem;
  clearsize = csz - SIZE_SZ;
  nclears = clearsize / sizeof (INTERNAL_SIZE_T);
  assert (nclears >= 3);
  //后面都是清0，else部分暂时不太理解
  if (nclears > 9)
    return memset (d, 0, clearsize);

  else
    {
      *(d + 0) = 0;
      *(d + 1) = 0;
      *(d + 2) = 0;
      if (nclears > 4)
        {
          *(d + 3) = 0;
          *(d + 4) = 0;
          if (nclears > 6)
            {
              *(d + 5) = 0;
              *(d + 6) = 0;
              if (nclears > 8)
                {
                  *(d + 7) = 0;
                  *(d + 8) = 0;
                }
            }
        }
    }

  return mem;
}
#endif /* IS_IN (libc) */

/*
   ------------------------------ malloc ------------------------------
 */

static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

#if USE_TCACHE
  size_t tcache_unsorted_count;	    /* count of unsorted chunks processed */
#endif

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size returns false for request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */
  //将bytes 进行normalize  规范成能容下bytes且满足对齐要求的最小chunk大小，放到nb中
  if (!checked_request2size (bytes, &nb))
    {
      __set_errno (ENOMEM);
      return NULL;
    }

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
     //一般情况下av !=NULL；
     //1.在arena数量已满但是当前线程thread_arena还没创建过，那么arena_get会返回null，并传递到这
     //2.在arena数量未满但是地址空间不足以申请一个最小的heap(HEAP_MIN_SIZE)来创建arena，那么arena_get会返回null，并传递到这
     //在上述情况下，会退化到直接通过sysmalloc来申请内存
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);//sysmalloc handles malloc cases requiring more memory from the system
      if (p != NULL)
	alloc_perturb (p, bytes);//如果perturb_byte存在，，对bytes字节的内容按特定字节进行memset，注意不包含nb中可能多出的字节
      return p;
    }

  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

#define REMOVE_FB(fb, victim, pp)			\
  do							\
    {							\
      victim = pp;					\
      if (victim == NULL)				\
	break;						\//获取解除指针保护的原始指针
      pp = REVEAL_PTR (victim->fd);                                     \
      if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))      \//检测对齐
	malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
    }							\//CAS 操作直到成功从FASTBIN中获取到一个victim(malloc_chunk)
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
	 != victim);					\ 

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))//在fastbin范围内
    {
      idx = fastbin_index (nb);//nb to fastbin index
      mfastbinptr *fb = &fastbin (av, idx);//获取第一个指向fastbin的指针
      mchunkptr pp;
      victim = *fb;//victim，指向fastbin的指针（实际就是一个malloc_chunk）

      if (victim != NULL)//指向的malloc_chunk存在
	{
	  if (__glibc_unlikely (misaligned_chunk (victim)))//对齐检查
	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);//像是单线程版本
	  else
	    REMOVE_FB (fb, pp, victim);//多线程版本，让fb指向下一个malloc_chunk，victim指向取出的fastbin；分配与释放都从头部，LIFO，后入先出
	  if (__glibc_likely (victim != NULL))//取出的fastbin存在
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));//重新获取victim所对应的fastbin索引
	      if (__builtin_expect (victim_idx != idx, 0))//结果很可能人为为假，一般就是应该是一样的
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);//依据当前使用的arean 取出的fastbin  规范化的bytes进行一系列检查，也是防止人为利用
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
     //如果nb也属于tcache范围，那么将直接从fastbin中获取chunk放入tcachebin,直到*fb链表空或者tcachebin满为止
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)//nb属于tcache范围内
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (__glibc_unlikely (misaligned_chunk (tc_victim)))
			malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
		      if (SINGLE_THREAD_P)
        //将fastbin中的后续chunk取出，放到tcachebin中，直到tcachebin满或者fastbin中下一个为NULL为止
			*fb = REVEAL_PTR (tc_victim->fd);
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}

		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;//将找到的chunck返回
	    }
	}
    }

  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))//在smallbin范围
    {
      idx = smallbin_index (nb);//nb to index
      bin = bin_at (av, idx);//使用起来如同直接使用mbinptr

      if ((victim = last (bin)) != bin)//如果bin不是指向自己(指向自己说明不存在对应的bin)；采用FIFO，从尾部分配，而释放的加入到头部
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))//检测
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);//让虚拟地址上紧挨着的下一个chunk的prev_inuse置1
          bin->bk = bck;
          bck->fd = bin;//将victim从链表中移除

          if (av != &main_arena)
	    set_non_main_arena (victim);//标记chunk为非主分配区内容
          check_malloced_chunk (av, victim, nb);//same as check_remalloced_chunk = do_check_remalloced_chunk 基本上能检查的都给检查了
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)//如果启用了tcache机制，并且属于tc_index在tcache范围内
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)//tcache未满且smallbin未空，则类似fastbin中的处理，将small list中chunk移除并放到tcache中;相比fastbin，多了一步设置prev_inuse;
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);//fastbin对应此处没有这个操作，是因为fastbin/tcache的prev_inuse都为1
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);//依据normalized bytes计算largebin_index
      //atomic_load含义应该是指加载读取原子操作
      //relaxed目前觉得和内存一致性模型相关，关键词：Relaxed Memory Model
      //暂时理解为如果该标识为真，进行consolideate
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);//consolidate之后，这个变量就会被设置为false
    }

    //到这说明如果是smallbin,说明其对应的链表为空了，但没进行consolidate;
    //或者如果是largebin，说明可能进行了consolidate(fastchunks存在合并，不存在则不合并)
  /*
     Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
   */

#if USE_TCACHE  //初始化一些值
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
    tcache_nb = nb;
  //如果填充过tcache，那么该变量就会设为1
  int return_cached = 0;
  //初始化为0，用于计数移出unsortedbin且不是填充tcache的chunk数
  //当 tcache_unsorted_count > mp_.tcache_unsorted_limit 且 return_cached为1，那么就直接从tcache中取出chunk返回,防止处理unsortedbin过程占用太多时间
  tcache_unsorted_count = 0;
#endif

  for (;; )
    {
      int iters = 0;
      //unsorted chunks bk不指向自己，说明列表非空;victim为列表尾部chunk;采用FIFO，头部放入，尾部取出
      //unsortedbin非空，进入while循环
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          size = chunksize (victim);//当前处理的victim的大小
          mchunkptr next = chunk_at_offset (victim, size);//虚拟地址上紧挨着的下一个chunk

          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)//一堆安全检测
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */
          //这一块简而言之就是unsortedbin中唯一chunk就是lastremainder,而且满足拆分出nb字节的smallbinchunk后还能大于MINSIZE，则拆分它，并返回chunk
          if (in_smallbin_range (nb) &&//说明申请nb属于small bin
              bck == unsorted_chunks (av) &&//说明是unsortedbin中最后一个chunk
              victim == av->last_remainder &&//说明这个chunk是last_remainder :The remainder from the most recent split of a small request 最近拆分的 small request 的剩余部分
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))//说明可以拆分last remainder 
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;//拆分last remainder
              av->last_remainder = remainder;//设置arena 的 last remainder属性
              remainder->bk = remainder->fd = unsorted_chunks (av);//设置unsorted 链表
              if (!in_smallbin_range (remainder_size))//remainder不在small bin范围内，设置相关指针;unsortedbin中的chunk(属于largebin范围),fd/bk_nextsize必须都为NULL
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }
              //个人理解此处设置prev_inuse，是为了满足A/F chunk的递归关系，Free chunk之前的chunk prev_inuse必定为1
              set_head (victim, nb | PREV_INUSE | 
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);//检测分配的chunk
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);//将victim从列表中移出

          /* Take now instead of binning if exact fit */

          if (size == nb)//刚好和需要的size大小一样
            {
              set_inuse_bit_at_offset (victim, size);//设置相关prev_inuse标识
              if (av != &main_arena)
		set_non_main_arena (victim);//有需要就设置非main arena标志
#if USE_TCACHE
	      /* Fill cache first, return to user only if cache fills.
		 We may return one of these chunks later.  */
	      if (tcache_nb
		  && tcache->counts[tc_idx] < mp_.tcache_count)
		{//这一步说明申请的nb属于tcache范围，对应所属tcachebin未满，且当前unsortedbin中处理的victim大小等同申请需要的大小
		  tcache_put (victim, tc_idx);
		  return_cached = 1;//标识填充过tcachebin,可以从tcachebin中返回
		  continue;//while循环处理unsorted bin
		}
	      else
		{
#endif        //到这说明申请的nb不属于tcache范围，且当前unsortedbin中处理的victim大小等同申请需要的大小，则进行返回
              //或者说明申请的nb属于tcache范围，对应所属tcachebin已满，且当前unsortedbin中处理的victim大小等同申请需要的大小，则进行返回
              check_malloced_chunk (av, victim, nb);//检测
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
		}
#endif
            }

          //如果size和nb不一样,会到此处
          //这里会将当前的victim放入对应的bin中
          /* place chunk in bin */
          if (in_smallbin_range (size))//如果在small bin 范围内
            {//此处记录size对应的smallbin链表
              victim_index = smallbin_index (size);
              //后面最终会插入在bck fwd之间，位于smallbin的头部，这里先记录链表相关信息
              bck = bin_at (av, victim_index);//待插入位置前一个地址;
              fwd = bck->fd;//带插入位置的后一个地址;
            }
          else
            {//large bin ; 每个索引位置的bin都包含了一个区间范围，其中chunk按大小递减排序
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);//待插入位置前一个地址 但只是初步的值
              fwd = bck->fd;//带插入位置的后一个地址，但只是初步的值，默认这么设是是假定比头第一个chunk大来思考的，
              //后面代码会调整，直到位置满足largebin中chunk排序从大大小(对应从头到尾)
              

              /* maintain large bins in sorted order */
              if (fwd != bck)//说明largebin中存在chunk
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;//这里设置PREV_INUSE暂时不清楚是为什么
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));//断言是main arena ,暂时不太明白为什么，猜测：难道是因为放入unsorted bin中的chunk一定会设置？目前来看unsortedbin中分配lastremainder时，会设置该main_arena
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
                    {//小于链表最后一个的大小，插入到到尾部
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert (chunk_main_arena (fwd));//断言是main arena 
                      while ((unsigned long) size < chunksize_nomask (fwd))//从头往后，找到第一个不大于size的fwd
                        {
                          fwd = fwd->fd_nextsize;
			  assert (chunk_main_arena (fwd));//断言是main arena  
                        }

                      if ((unsigned long) size
			  == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;//如果size和chunksize相等，插入在紧跟着的第二个位置
                      else
                        {//size>fwd   将victim插入在fwd前一个位置，并且这个size之前的链表中没有，属于新的大小
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;//维护largebin中的fd/bk nextsize，因为即将插入的地方，里面只有victim
            }

          mark_bin (av, victim_index);//将bitmap置位,表示对应的bin存在chunk；bin为空时，不会改变置位，只有后面serach时发现bin为空才会清0
          victim->bk = bck;//将当前unsorted bin 中的victim插入到对应small/large的bin中
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#if USE_TCACHE
      /* If we've processed as many chunks as we're allowed while
	 filling the cache, return one of the cached ones.  */
      ++tcache_unsorted_count;   
      if (return_cached
	  && mp_.tcache_unsorted_limit > 0  //默认为0，无限制，不会提前通过tcahce返回；Maximum number of chunks to remove from the unsorted list, which aren't used to prefill the cache
	  && tcache_unsorted_count > mp_.tcache_unsorted_limit)//当处理了足够多的unsorted_chunk后，从tcache中获取一个返回；主要用于提高分配速度，避免在unsorted chunk处理太长时间
	{
	  return tcache_get (tc_idx);
	}
#endif

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)//超出10000次循环后，break while循环，停止unsortedbin处理，防止处理消耗太多时间
            break;
        }//此处while结尾

#if USE_TCACHE
      /* If all the small chunks we found ended up cached, return one now.  */
      //如果上面所有unsortedbin chunk处理完，且tcahce放置过chunk
      //或者处理了10000次unsortedchunk，且tcache放置过chunk
      //则立马取出缓存中的一个进行返回
      if (return_cached)
	{
	  return tcache_get (tc_idx);
	}
#endif

      /*
         If a large request, scan through the chunks of current bin in
         sorted order to find smallest that fits.  Use the skip list for this.
       */

      if (!in_smallbin_range (nb))//一般是largebin；  如果之前unsortedbin中不存在nb大小的chunk，那么可能走到这仍然时smallrange范围内的bin，这种情况下此处不执行，往下走
        {
          bin = bin_at (av, idx);//利用largebin idx找到对应链表头

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin
	      && (unsigned long) chunksize_nomask (victim)
	        >= (unsigned long) (nb))//largebin最大值大于nb
            {
              victim = victim->bk_nextsize;//看这个样子是从后往前找，即从小往大找，找到第一个满足要求的victim  : victim >=nb
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;

              /* Avoid removing the first entry for a size so that the skip
                 list does not have to be rerouted.  */
              if (victim != last (bin)
		  && chunksize_nomask (victim)
		    == chunksize_nomask (victim->fd))
                victim = victim->fd;//先避免移出找到的victim，而是移出相同大小的下一个victim   这样就不需要维护nextsize等指针

              remainder_size = size - nb;//记录remainder size
              unlink_chunk (av, victim);//将victim从链表中移出

              /* Exhaust */
              if (remainder_size < MINSIZE)//如果分裂的话不满足MINSIZE要求，即没办法分裂成两个chunk
                {
                  set_inuse_bit_at_offset (victim, size);//设置相关prev_inuse标识
                  if (av != &main_arena)
		    set_non_main_arena (victim);//取出的时候，会设置相关arena标识
                }
              /* Split */
              else//对从bin中取出的chunk进行分裂;分裂后新的victim返回，而remainder加入到unsorted_chunks头部
                {
                  remainder = chunk_at_offset (victim, nb);
                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size))//如果不是small bin 清空nextsize
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);//检查
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }

      /*访问bins中的下一个bin，采取最佳适配原则，找到满足要求的最小chunk
         Search for a chunk by scanning bins, starting with next largest
         bin. This search is strictly by best-fit; i.e., the smallest
         (with ties going to approximately the least recently used) chunk
         that fits is selected.

         The bitmap avoids needing to check that most blocks are nonempty.
         The particular case of skipping all bins during warm-up phases
         when no chunks have been returned yet is faster than it might look.
       */
      //到这，说明无论是smallbin还是largebin，nb字节对应bin都无法满足，则通过最小适配原则匹配
      //++idx从下一个bin开始尝试
      ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);//idx/32
      map = av->binmap[block];//32bit一个word进行检测
      bit = idx2bit (idx);//对应变量map（word）的bit位置（1 << [0,31]）

      for (;; )//这里的查找应该是覆盖了small bin 和large bin
        {
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)// bit>map说明不存在满足需要的chunk,要找下一个block；0的情况由于binmap信息不及时，后面继续左移查找时(1<<31)<<1溢出了，看后面分析
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;//没找到就去use top
                }
              while ((map = av->binmap[block]) == 0);

              bin = bin_at (av, (block << BINMAPSHIFT));//到这说明*可能*存在空闲的chunk可以满足
              bit = 1;//尝试从最低位开始查找
            }

          /* Advance to bin with set bit. There must be one. */
          while ((bit & map) == 0)//从低到高，找到第一个能满足的bin
            {
              bin = next_bin (bin);
              bit <<= 1;
              assert (bit != 0);
            }

          /* Inspect the bin. It is likely to be non-empty */
          victim = last (bin);//获取最后一个bin，如果是smallbin，第一个和最后一个没有区别；如果是largebin，则尝试获取最小bin

          /*  If a false alarm (empty bin), clear the bit. */
          if (victim == bin)//说明不存在，bitmap的信息是假的，更新binmap信息
            {
              av->binmap[block] = map &= ~bit; /* Write through */  //第一次查找错误时更新bitmap信息
              bin = next_bin (bin);
              bit <<= 1;//设置为下一个bin开始查找，如果是这样，那么bit可能就会为0了
              //再次循环
            }
          else
            {//说明找到了
              size = chunksize (victim);

              /*  We know the first chunk in this bin is big enough to use. */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb;

              /* unlink */
              unlink_chunk (av, victim);

              /* Exhaust */
              //基本和前面一样，如果分裂后不能变成两个chunk，就不分裂
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }

              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks 2");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;//将remainder加入unsorted bin头

                  /* advertise as last remainder */
                  //如果申请的内存属于small bin，则更新av的last remainder；目前来看应该是只有申请smallbin时，剩余部分才会更新到last_reaminder;
                  //注意，没有被分裂的chunk必须属于smallbin，只是说申请的chunk要属于smallbinrange范围
                  if (in_smallbin_range (nb))            
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }

    use_top://个人理解通常刚开始时，bin中不存在任何chunk，会进入此处通过topchunk进行分配
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */

      victim = av->top;
      size = chunksize (victim);

      if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");

      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))//如果能分裂，则进行分配并分裂top
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }

      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
      else if (atomic_load_relaxed (&av->have_fastchunks))//top不够分配了，如果可以尝试合并fastbin,则合并后再次进入for循环尝试分配
        {//这种情况出现应该主要是unsortedbin处理之前smallbin分配时但smallbin链表为空，接下来topchunk也不够分配nb smallchunk，那么尝试合并fastbin再分配
        //一般而言是top不够分配smallbin chunk,值得进行合并fastbin并接着尝试再unsortedbin中进行分配
          malloc_consolidate (av);
          /* restore original bin index */
          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);
          else
            idx = largebin_index (nb);
        }

      /*
         Otherwise, relay to handle system-dependent cases
       */
      else
        {//top chunk 不满足  也无法合并fastchunk
          void *p = sysmalloc (nb, av);//直接向系统分配内存
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}

/*
   ------------------------------ free ------------------------------
 */
//除了_libc_free会调用该方法，realloc _int_memalignd等也会调用
static void
_int_free (mstate av, mchunkptr p, int have_lock)//have_lock表明调用时，其av是否占用了mutex锁，0表示没有，1表示有
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  size = chunksize (p);//p对应的chunk size

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)//p在地址空间的尾部，加size就溢出地址空间了，不允许发生在地址空间的尾部
      || __builtin_expect (misaligned_chunk (p), 0))//对齐检测
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))//size检测
    malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);//一堆检测

#if USE_TCACHE//启用了tcache机制
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)//tcache初始化了并且size属于tcache范围
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache_key))//tcache_put时会设置tcache_key;如果出现了相等的巧合，遍历链表来确认是否为double free
	  {
	    tcache_entry *tmp;
	    size_t cnt = 0;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = REVEAL_PTR (tmp->next), ++cnt)//遍历对应的tcache链表
	      {
		if (cnt >= mp_.tcache_count)//检测是否有过多的tcache_count
		  malloc_printerr ("free(): too many chunks detected in tcache");
		if (__glibc_unlikely (!aligned_OK (tmp)))//对齐检测
		  malloc_printerr ("free(): unaligned chunk detected in tcache 2");
		if (tmp == e)//检测到double free
		  malloc_printerr ("free(): double free detected in tcache 2");/* Abort with an error message.  */
		/* If we get here, it was a coincidence.  We've wasted a
		   few cycles, but don't abort.  */
	      }
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)//tcahce未满
	  {
	    tcache_put (p, tc_idx);//释放到tchach put,这时prev_inuse为1
	    return;
	  }
      }
  }
#endif

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */
 //不属于tcahce范围或者tcachebin已满
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())//属于fastbin

#if TRIM_FASTBINS//默认为0；TRIM_FASTBINS controls whether free() of a very small chunk can immediately lead to trimming
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)//如果使用了TRIM_FASTBINS并且p对应的chunk没有挨着top chunk
#endif
      ) {

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))//检测next chunk的chunksize是否合理，不合理则进入fail
      {
	bool fail = true;
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	if (!have_lock)//__libc_free进入的时候值为0;从sysmalloc进入时，则为1(这时是为了将oldtop除去fencepost后剩余部分进行释放，新top指向了下一个新heap中)
	  {
	    __libc_lock_lock (av->mutex);//加锁后再尝试，防止之前的检测是因为并发造成fail=true
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);//如果设置了perturb_byte,将要回收的内存进行填充，防止信息泄漏，目前来看perturb_byte为0，什么也不做

    atomic_store_relaxed (&av->have_fastchunks, true);//设置have_fastchunks true；consolidate时会设置其为false；用以表示是否可以对fastbin进行合并
    unsigned int idx = fastbin_index(size);//获取要回收的chunk要放置的链表头的位置
    fb = &fastbin (av, idx);//获取链表头

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)//单线程环境，加入fastbin
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = PROTECT_PTR (&p->fd, old);
	*fb = p;
      }
    else
      do//多线程环境处理,加入fastbin
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  old2 = old;
	  p->fd = PROTECT_PTR (&p->fd, old);//这时prev_inuse为1
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);//cas操作，检测并发是否修改了表头，如果是的话就再次尝试

    /* Check that size of fastbin chunk at the top is the same as
       size of the chunk that we are adding.  We can dereference OLD
       only if we have the lock, otherwise it might have already been
       allocated again.  */
    if (have_lock && old != NULL
	&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))//检测原先链表中的entry是否有问题
      malloc_printerr ("invalid fastbin entry (free)");
  }//fastbin结束，程序返回

  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {//chunk is not mapped的情况处理；隐含chunksize > fastbin max size

    /* If we're single-threaded, don't lock the arena.  */
    //如果是单线程环境（通常通过类似‘multiple_threads’ field进行检测）
    if (SINGLE_THREAD_P)//优化后面加锁
      have_lock = true;

    if (!have_lock)
      __libc_lock_lock (av->mutex);//非单线程环境对arena进行加锁

    nextchunk = chunk_at_offset(p, size);//获取下一个chunk

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))//如果p是topchunk,那么可能是double free或者错误发生
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    //The initial  value coms from MORECORE_CONTIGUOUS,default 1: consecutive calls to MORECORE with positive arguments always reurn  contiguous increasing addresses.
    if (__builtin_expect (contiguous (av)//只有主arena可能是连续的
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))//nextchunk地址是否大于top所占的最高地址，说明出现了错误
	malloc_printerr ("double free or corruption (out)");
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))//nextchunk的prev_inuse检测
      malloc_printerr ("double free or corruption (!prev)");

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))//nextchunk size大小检测
      malloc_printerr ("free(): invalid next size (normal)");

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);//如果设置了perturb_byte,将要回收的内存进行填充，防止信息泄漏，目前来看perturb_byte为0，什么也不做

    /* consolidate backward */
    if (!prev_inuse(p)) {//前一个chunk是free
      prevsize = prev_size (p);
      size += prevsize;//consolidate chunk后的大小
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))//地址偏移计算后，验证prevsize是否正确
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);//将p从原先的空闲链表中取出
    }

    if (nextchunk != av->top) {//nextchunk不为top
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);//next chunk是否正在使用

      /* consolidate forward */
      if (!nextinuse) {
	unlink_chunk (av, nextchunk);//将nextchunk合并
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);//不合并则清空nextchunk的prev_inuse

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);//unsorted chunk 头
      fwd = bck->fd;//unsorted chunk链表中的第一个
      if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("free(): corrupted unsorted chunks");
      p->fd = fwd;
      p->bk = bck;//插入unsorted链表头 step1
      if (!in_smallbin_range(size))//如果是largechunk则要进行清空fd/bk nextsize
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;//插入unsorted链表头 step2
      //暂时不清楚为什么这里一定是这样，难道因为所有chunk都从这个规则开始，形成递归效应，前面的chunk必然是prev_inuse?
      //放入unsorted bin中的chunk的prev_inuse都被设置为1，应该是为了形成递归效应(A/F chunk的四条递归规则)
      set_head(p, size | PREV_INUSE);
      set_foot(p, size);//设置虚拟地址挨着的下一个chunk的mchunk_prev_size

      check_free_chunk(av, p);//一堆检测
    }

    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {//如果挨着top，则合并到top中
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }

    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {//如果size（相邻free合并后释放的大小）>= fastbin合并阈值（64K）,fastbin中存在数据，则触发fastbin的合并操作
      if (atomic_load_relaxed (&av->have_fastchunks))//fastbin存在数据
	malloc_consolidate(av);//合并fastbin

      if (av == &main_arena) {//是main_arena
//默认MORECORE_CANNOT_TRIM       NOT defined
#ifndef MORECORE_CANNOT_TRIM//未定义cannot trim时（即允许收缩）
	if ((unsigned long)(chunksize(av->top)) >=
	    (unsigned long)(mp_.trim_threshold))//如果top chunk的size  > trim_threshold
	  systrim(mp_.top_pad, av);//top_pad值默认为0；收缩；main arena 收缩方式
#endif
      } else {//非main_arena
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away.  */
	heap_info *heap = heap_for_ptr(top(av));

	assert(heap->ar_ptr == av);
	heap_trim(heap, mp_.top_pad);//非main arena收缩方式
      }
    }

    if (!have_lock)
      __libc_lock_unlock (av->mutex);
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {//mmaped方式,通过_libc_free调用_int_free是执行不到此处的；相比libc_free中释放mmap chunk，此处的释放不会更新mmap_threshold以及trim_threshold；
    munmap_chunk (p);//unmap对应的chunk
  }
}

/*
  ------------------------- malloc_consolidate -------------------------

  malloc_consolidate is a specialized version of free() that tears
  down chunks held in fastbins.  Free itself cannot be used for this
  purpose since, among other things, it might place chunks back onto
  fastbins.  So, instead, we need to use a minor variant of the same
  code.
*/
//从后往前，从大到小遍历所有fastbin，并对fastchunk的前后chunk尝试进行合并
//合并后的chunk如果不挨着topchunk则放入unsortedbin
//合并后的chunk如果挨着topchunk则并入topchunk
//合并过程中，前后chunk如果是freechunk，那么freechunk会从原先的bins链表（unsorted/smallbin/largebin）unlink，再合并
//为什么这里只需要尝试合并前后chunk就可以呢？可以参考https://www.bilibili.com/video/BV1tL4y1Y72y?share_source=copy_web
//这里讲述了Allocated/Free chunk的递归分析
static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;
  //consolidate之后，这个变量就会被设置为false;刚创建arean的时候，这个值也为false
  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);//获取unsorted_bin头

  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1);//获取数组中理论最大的fastbin ptr's ptr
  fb = &fastbin (av, 0);//获取数组中理论理论最小fastbin ptr ‘s ptr
  do {
    //Store NEWVALUE(NULL) in *MEM(fb) and return the old value.  
    //相当于p=*fb   *fb=NULL  fb本身是不变的
    p = atomic_exchange_acq (fb, NULL);
    if (p != 0) {
      do {
	{
	  if (__glibc_unlikely (misaligned_chunk (p)))//对齐检查
	    malloc_printerr ("malloc_consolidate(): "
			     "unaligned fastbin chunk detected");

	  unsigned int idx = fastbin_index (chunksize (p));
	  if ((&fastbin (av, idx)) != fb)//地址方面检查
	    malloc_printerr ("malloc_consolidate(): invalid chunk size");
	}

	check_inuse_chunk(av, p);//inuse check
	nextp = REVEAL_PTR (p->fd);//链表中下一个地址

	/* Slightly streamlined version of consolidation code in free() */
	size = chunksize (p);
	nextchunk = chunk_at_offset(p, size);//虚拟地址上紧挨着的下一个chunk位置
	nextsize = chunksize(nextchunk);//虚拟地址上紧挨着的下一个chunk的大小

	if (!prev_inuse(p)) {//前置chunk为free
	  prevsize = prev_size (p);
	  size += prevsize;//记录free大小
	  p = chunk_at_offset(p, -((long) prevsize));
	  if (__glibc_unlikely (chunksize(p) != prevsize))
	    malloc_printerr ("corrupted size vs. prev_size in fastbins");
	  unlink_chunk (av, p);//Take a chunk off a bin list. 将prev chunk从freelist中取出
	}

	if (nextchunk != av->top) {//如果下一个chunk不是top chunk，放入unsorted bin
	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	  if (!nextinuse) {//next chunk not in use
	    size += nextsize;//记录free大小
	    unlink_chunk (av, nextchunk);//将next chunk从freelist中取出
	  } else
	    clear_inuse_bit_at_offset(nextchunk, 0);//将next chunk 的prev inuse清0，表明unsortedbin中chunk被视为free

	  first_unsorted = unsorted_bin->fd;
	  unsorted_bin->fd = p;
	  first_unsorted->bk = p;//插入unsorted bin step1，将p的前后chunk链表指针关系进行维护,放入表头

	  if (!in_smallbin_range (size)) {//存放在unsortedbin中的largechunk，会设置fd/bk_nextsize都为NULL
	    p->fd_nextsize = NULL;
	    p->bk_nextsize = NULL;
	  }

	  set_head(p, size | PREV_INUSE);//设置consolidate后的chunk的size
	  p->bk = unsorted_bin;
	  p->fd = first_unsorted;//插入unsorted bin step2，将p本身的链表指针关系维护好
	  set_foot(p, size);//设置合并后chunk的prev_size（虚拟地址上下一个chunk的prev_size）
	}

	else {//是topchunk,则合并进top chunk，如果递归这样考虑，topchunk前面的chunk必然不是free的
	  size += nextsize;
	  set_head(p, size | PREV_INUSE);
	  av->top = p;
	}

      } while ( (p = nextp) != 0);//p所在的链表不为空，就继续直到链表为空

    }
  } while (fb++ != maxfb);//遍历fastbin中所有的理论上可用链表；实际fastbin不一定会用到整个数组，只用一部分，没用部分初始化时默认为NULL,不影响
}

/*
  ------------------------------ realloc ------------------------------
*/
//此处是非mmapchunk的处理，不包括mmap chunk；进入时锁定了arena
static void *
_int_realloc (mstate av, mchunkptr oldp, INTERNAL_SIZE_T oldsize,
	     INTERNAL_SIZE_T nb)
{
  mchunkptr        newp;            /* chunk to return */
  INTERNAL_SIZE_T  newsize;         /* its size */
  void*          newmem;          /* corresponding user mem */

  mchunkptr        next;            /* next contiguous chunk after oldp */

  mchunkptr        remainder;       /* extra space at end of newp */
  unsigned long    remainder_size;  /* its size */

  /* oldmem size */
  if (__builtin_expect (chunksize_nomask (oldp) <= CHUNK_HDR_SZ, 0)
      || __builtin_expect (oldsize >= av->system_mem, 0))
    malloc_printerr ("realloc(): invalid old size");

  check_inuse_chunk (av, oldp);

  /* All callers already filter out mmap'ed chunks.  */
  assert (!chunk_is_mmapped (oldp));

  next = chunk_at_offset (oldp, oldsize);
  INTERNAL_SIZE_T nextsize = chunksize (next);
  if (__builtin_expect (chunksize_nomask (next) <= CHUNK_HDR_SZ, 0)
      || __builtin_expect (nextsize >= av->system_mem, 0))
    malloc_printerr ("realloc(): invalid next size");

  if ((unsigned long) (oldsize) >= (unsigned long) (nb))//至于此处没有SIZE_SZ的原因是mmap chunk就唯一一个chunk，此处后面必然还有chunk(当前chunk不可能是topchunk)
    {
      /* already big enough; split below */
      newp = oldp;
      newsize = oldsize;
    }

  else
    {
      /* Try to expand forward into top */
      if (next == av->top &&
          (unsigned long) (newsize = oldsize + nextsize) >=
          (unsigned long) (nb + MINSIZE))//如果可以，就沿着top扩展chunk
        {
          set_head_size (oldp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
          av->top = chunk_at_offset (oldp, nb);
          set_head (av->top, (newsize - nb) | PREV_INUSE);
          check_inuse_chunk (av, oldp);
          return tag_new_usable (chunk2mem (oldp));
        }

      /* Try to expand forward into next chunk;  split off remainder below */
      else if (next != av->top &&
               !inuse (next) &&
               (unsigned long) (newsize = oldsize + nextsize) >=
               (unsigned long) (nb))//next不为top，但是为free，且内存足够，则合并当前chunk和nextchunk，并之后split
        {
          newp = oldp;
          unlink_chunk (av, next);
        }

      /* allocate, copy, free */
      else//到此处，说明无法扩展，只能申请/拷贝/释放达到目标
        {
          newmem = _int_malloc (av, nb - MALLOC_ALIGN_MASK);
          if (newmem == 0)
            return 0; /* propagate failure */

          newp = mem2chunk (newmem);
          newsize = chunksize (newp);

          /*
             Avoid copy if newp is next chunk after oldp.
           */
          if (newp == next)//发生相等的原因猜测是_int_malloc期间发生了合并操作，比如malloc_consolidate，造成了现在的结果
            {
              newsize += oldsize;
              newp = oldp;
            }
          else//真实进行拷贝与释放
            {
	      void *oldmem = chunk2mem (oldp);
	      size_t sz = memsize (oldp);
	      (void) tag_region (oldmem, sz);
	      newmem = tag_new_usable (newmem);
	      memcpy (newmem, oldmem, sz);
	      _int_free (av, oldp, 1);
	      check_inuse_chunk (av, newp);
	      return newmem;
            }
        }
    }

  /* If possible, free extra space in old or extended chunk */

  assert ((unsigned long) (newsize) >= (unsigned long) (nb));

  remainder_size = newsize - nb;

  if (remainder_size < MINSIZE)   /* not enough extra to split off */
    {
      set_head_size (newp, newsize | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_inuse_bit_at_offset (newp, newsize);
    }
  else   /* split remainder */
    {
      remainder = chunk_at_offset (newp, nb);
      /* Clear any user-space tags before writing the header.  */
      remainder = tag_region (remainder, remainder_size);
      set_head_size (newp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE |
                (av != &main_arena ? NON_MAIN_ARENA : 0));
      /* Mark remainder as inuse so free() won't complain */
      set_inuse_bit_at_offset (remainder, remainder_size);
      _int_free (av, remainder, 1);//释放remainder
    }

  check_inuse_chunk (av, newp);
  return tag_new_usable (chunk2mem (newp));
}

/*
   ------------------------------ memalign ------------------------------
 */

static void *
_int_memalign (mstate av, size_t alignment, size_t bytes)
{
  INTERNAL_SIZE_T nb;             /* padded  request size */
  char *m;                        /* memory returned by malloc call */
  mchunkptr p;                    /* corresponding chunk */
  char *brk;                      /* alignment point within p */
  mchunkptr newp;                 /* chunk to return */
  INTERNAL_SIZE_T newsize;        /* its size */
  INTERNAL_SIZE_T leadsize;       /* leading space before alignment point */
  mchunkptr remainder;            /* spare room at end to split off */
  unsigned long remainder_size;   /* its size */
  INTERNAL_SIZE_T size;



  if (!checked_request2size (bytes, &nb))
    {
      __set_errno (ENOMEM);
      return NULL;
    }

  /*
     Strategy: find a spot within that chunk that meets the alignment
     request, and then possibly free the leading and trailing space.
   */

  /* Call malloc with worst case padding to hit alignment. */

  m = (char *) (_int_malloc (av, nb + alignment + MINSIZE));

  if (m == 0)
    return 0;           /* propagate failure */

  p = mem2chunk (m);

  if ((((unsigned long) (m)) % alignment) != 0)   /* misaligned */

    { /*
                Find an aligned spot inside chunk.  Since we need to give back
                leading space in a chunk of at least MINSIZE, if the first
                calculation places us at a spot with less than MINSIZE leader,
                we can move to the next aligned spot -- we've allocated enough
                total room so that this is always possible.
                 */
      brk = (char *) mem2chunk (((unsigned long) (m + alignment - 1)) &
                                - ((signed long) alignment));
      if ((unsigned long) (brk - (char *) (p)) < MINSIZE)
        brk += alignment;

      newp = (mchunkptr) brk;
      leadsize = brk - (char *) (p);
      newsize = chunksize (p) - leadsize;

      /* For mmapped chunks, just adjust offset */
      if (chunk_is_mmapped (p))
        {
          set_prev_size (newp, prev_size (p) + leadsize);
          set_head (newp, newsize | IS_MMAPPED);
          return chunk2mem (newp);
        }

      /* Otherwise, give back leader, use the rest */
      set_head (newp, newsize | PREV_INUSE |
                (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_inuse_bit_at_offset (newp, newsize);
      set_head_size (p, leadsize | (av != &main_arena ? NON_MAIN_ARENA : 0));
      _int_free (av, p, 1);
      p = newp;

      assert (newsize >= nb &&
              (((unsigned long) (chunk2mem (p))) % alignment) == 0);
    }

  /* Also give back spare room at the end */
  if (!chunk_is_mmapped (p))
    {
      size = chunksize (p);
      if ((unsigned long) (size) > (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (p, nb);
          set_head (remainder, remainder_size | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head_size (p, nb);
          _int_free (av, remainder, 1);
        }
    }

  check_inuse_chunk (av, p);
  return chunk2mem (p);
}


/*
   ------------------------------ malloc_trim ------------------------------
 */

static int
mtrim (mstate av, size_t pad)
{
  /* Ensure all blocks are consolidated.  */
  malloc_consolidate (av);

  const size_t ps = GLRO (dl_pagesize);
  int psindex = bin_index (ps);
  const size_t psm1 = ps - 1;

  int result = 0;
  for (int i = 1; i < NBINS; ++i)
    if (i == 1 || i >= psindex)
      {
        mbinptr bin = bin_at (av, i);

        for (mchunkptr p = last (bin); p != bin; p = p->bk)
          {
            INTERNAL_SIZE_T size = chunksize (p);

            if (size > psm1 + sizeof (struct malloc_chunk))
              {
                /* See whether the chunk contains at least one unused page.  */
                char *paligned_mem = (char *) (((uintptr_t) p
                                                + sizeof (struct malloc_chunk)
                                                + psm1) & ~psm1);

                assert ((char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ
			<= paligned_mem);
                assert ((char *) p + size > paligned_mem);

                /* This is the size we could potentially free.  */
                size -= paligned_mem - (char *) p;

                if (size > psm1)
                  {
#if MALLOC_DEBUG
                    /* When debugging we simulate destroying the memory
                       content.  */
                    memset (paligned_mem, 0x89, size & ~psm1);
#endif
                    __madvise (paligned_mem, size & ~psm1, MADV_DONTNEED);

                    result = 1;
                  }
              }
          }
      }

#ifndef MORECORE_CANNOT_TRIM
  return result | (av == &main_arena ? systrim (pad, av) : 0);

#else
  return result;
#endif
}


int
__malloc_trim (size_t s)
{
  int result = 0;

  if (!__malloc_initialized)
    ptmalloc_init ();

  mstate ar_ptr = &main_arena;
  do
    {
      __libc_lock_lock (ar_ptr->mutex);
      result |= mtrim (ar_ptr, s);
      __libc_lock_unlock (ar_ptr->mutex);

      ar_ptr = ar_ptr->next;
    }
  while (ar_ptr != &main_arena);

  return result;
}


/*
   ------------------------- malloc_usable_size -------------------------
 */

static size_t
musable (void *mem)
{
  mchunkptr p;
  if (mem != 0)
    {
      size_t result = 0;

      p = mem2chunk (mem);

      if (chunk_is_mmapped (p))
	result = chunksize (p) - CHUNK_HDR_SZ;
      else if (inuse (p))
	result = memsize (p);

      return result;
    }
  return 0;
}

#if IS_IN (libc)
size_t
__malloc_usable_size (void *m)
{
  size_t result;

  result = musable (m);
  return result;
}
#endif

/*
   ------------------------------ mallinfo ------------------------------
   Accumulate malloc statistics for arena AV into M.
 */
static void
int_mallinfo (mstate av, struct mallinfo2 *m)
{
  size_t i;
  mbinptr b;
  mchunkptr p;
  INTERNAL_SIZE_T avail;
  INTERNAL_SIZE_T fastavail;
  int nblocks;
  int nfastblocks;

  check_malloc_state (av);

  /* Account for top */
  avail = chunksize (av->top);
  nblocks = 1;  /* top always exists */

  /* traverse fastbins */
  nfastblocks = 0;
  fastavail = 0;

  for (i = 0; i < NFASTBINS; ++i)
    {
      for (p = fastbin (av, i);
	   p != 0;
	   p = REVEAL_PTR (p->fd))
        {
	  if (__glibc_unlikely (misaligned_chunk (p)))
	    malloc_printerr ("int_mallinfo(): "
			     "unaligned fastbin chunk detected");
          ++nfastblocks;
          fastavail += chunksize (p);
        }
    }

  avail += fastavail;

  /* traverse regular bins */
  for (i = 1; i < NBINS; ++i)
    {
      b = bin_at (av, i);
      for (p = last (b); p != b; p = p->bk)
        {
          ++nblocks;
          avail += chunksize (p);
        }
    }

  m->smblks += nfastblocks;
  m->ordblks += nblocks;
  m->fordblks += avail;
  m->uordblks += av->system_mem - avail;
  m->arena += av->system_mem;
  m->fsmblks += fastavail;
  if (av == &main_arena)
    {
      m->hblks = mp_.n_mmaps;
      m->hblkhd = mp_.mmapped_mem;
      m->usmblks = 0;
      m->keepcost = chunksize (av->top);
    }
}


struct mallinfo2
__libc_mallinfo2 (void)
{
  struct mallinfo2 m;
  mstate ar_ptr;

  if (!__malloc_initialized)
    ptmalloc_init ();

  memset (&m, 0, sizeof (m));
  ar_ptr = &main_arena;
  do
    {
      __libc_lock_lock (ar_ptr->mutex);
      int_mallinfo (ar_ptr, &m);
      __libc_lock_unlock (ar_ptr->mutex);

      ar_ptr = ar_ptr->next;
    }
  while (ar_ptr != &main_arena);

  return m;
}
libc_hidden_def (__libc_mallinfo2)

struct mallinfo
__libc_mallinfo (void)
{
  struct mallinfo m;
  struct mallinfo2 m2 = __libc_mallinfo2 ();

  m.arena = m2.arena;
  m.ordblks = m2.ordblks;
  m.smblks = m2.smblks;
  m.hblks = m2.hblks;
  m.hblkhd = m2.hblkhd;
  m.usmblks = m2.usmblks;
  m.fsmblks = m2.fsmblks;
  m.uordblks = m2.uordblks;
  m.fordblks = m2.fordblks;
  m.keepcost = m2.keepcost;

  return m;
}


/*
   ------------------------------ malloc_stats ------------------------------
 */

void
__malloc_stats (void)
{
  int i;
  mstate ar_ptr;
  unsigned int in_use_b = mp_.mmapped_mem, system_b = in_use_b;

  if (!__malloc_initialized)
    ptmalloc_init ();
  _IO_flockfile (stderr);
  int old_flags2 = stderr->_flags2;
  stderr->_flags2 |= _IO_FLAGS2_NOTCANCEL;
  for (i = 0, ar_ptr = &main_arena;; i++)
    {
      struct mallinfo2 mi;

      memset (&mi, 0, sizeof (mi));
      __libc_lock_lock (ar_ptr->mutex);
      int_mallinfo (ar_ptr, &mi);
      fprintf (stderr, "Arena %d:\n", i);
      fprintf (stderr, "system bytes     = %10u\n", (unsigned int) mi.arena);
      fprintf (stderr, "in use bytes     = %10u\n", (unsigned int) mi.uordblks);
#if MALLOC_DEBUG > 1
      if (i > 0)
        dump_heap (heap_for_ptr (top (ar_ptr)));
#endif
      system_b += mi.arena;
      in_use_b += mi.uordblks;
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = ar_ptr->next;
      if (ar_ptr == &main_arena)
        break;
    }
  fprintf (stderr, "Total (incl. mmap):\n");
  fprintf (stderr, "system bytes     = %10u\n", system_b);
  fprintf (stderr, "in use bytes     = %10u\n", in_use_b);
  fprintf (stderr, "max mmap regions = %10u\n", (unsigned int) mp_.max_n_mmaps);
  fprintf (stderr, "max mmap bytes   = %10lu\n",
           (unsigned long) mp_.max_mmapped_mem);
  stderr->_flags2 = old_flags2;
  _IO_funlockfile (stderr);
}


/*
   ------------------------------ mallopt ------------------------------
 */
static __always_inline int
do_set_trim_threshold (size_t value)
{
  LIBC_PROBE (memory_mallopt_trim_threshold, 3, value, mp_.trim_threshold,
	      mp_.no_dyn_threshold);
  mp_.trim_threshold = value;
  mp_.no_dyn_threshold = 1;
  return 1;
}

static __always_inline int
do_set_top_pad (size_t value)
{
  LIBC_PROBE (memory_mallopt_top_pad, 3, value, mp_.top_pad,
	      mp_.no_dyn_threshold);
  mp_.top_pad = value;
  mp_.no_dyn_threshold = 1;
  return 1;
}

static __always_inline int
do_set_mmap_threshold (size_t value)
{
  /* Forbid setting the threshold too high.  */
  if (value <= HEAP_MAX_SIZE / 2)
    {
      LIBC_PROBE (memory_mallopt_mmap_threshold, 3, value, mp_.mmap_threshold,
		  mp_.no_dyn_threshold);
      mp_.mmap_threshold = value;
      mp_.no_dyn_threshold = 1;
      return 1;
    }
  return 0;
}

static __always_inline int
do_set_mmaps_max (int32_t value)
{
  LIBC_PROBE (memory_mallopt_mmap_max, 3, value, mp_.n_mmaps_max,
	      mp_.no_dyn_threshold);
  mp_.n_mmaps_max = value;
  mp_.no_dyn_threshold = 1;
  return 1;
}

static __always_inline int
do_set_mallopt_check (int32_t value)
{
  return 1;
}

static __always_inline int
do_set_perturb_byte (int32_t value)
{
  LIBC_PROBE (memory_mallopt_perturb, 2, value, perturb_byte);
  perturb_byte = value;
  return 1;
}

static __always_inline int
do_set_arena_test (size_t value)
{
  LIBC_PROBE (memory_mallopt_arena_test, 2, value, mp_.arena_test);
  mp_.arena_test = value;
  return 1;
}

static __always_inline int
do_set_arena_max (size_t value)
{
  LIBC_PROBE (memory_mallopt_arena_max, 2, value, mp_.arena_max);
  mp_.arena_max = value;
  return 1;
}

#if USE_TCACHE
static __always_inline int
do_set_tcache_max (size_t value)
{
  if (value <= MAX_TCACHE_SIZE)
    {
      LIBC_PROBE (memory_tunable_tcache_max_bytes, 2, value, mp_.tcache_max_bytes);
      mp_.tcache_max_bytes = value;
      mp_.tcache_bins = csize2tidx (request2size(value)) + 1;
      return 1;
    }
  return 0;
}

static __always_inline int
do_set_tcache_count (size_t value)
{
  if (value <= MAX_TCACHE_COUNT)
    {
      LIBC_PROBE (memory_tunable_tcache_count, 2, value, mp_.tcache_count);
      mp_.tcache_count = value;
      return 1;
    }
  return 0;
}

static __always_inline int
do_set_tcache_unsorted_limit (size_t value)
{
  LIBC_PROBE (memory_tunable_tcache_unsorted_limit, 2, value, mp_.tcache_unsorted_limit);
  mp_.tcache_unsorted_limit = value;
  return 1;
}
#endif

static inline int
__always_inline
do_set_mxfast (size_t value)
{
  if (value <= MAX_FAST_SIZE)
    {
      LIBC_PROBE (memory_mallopt_mxfast, 2, value, get_max_fast ());
      set_max_fast (value);
      return 1;
    }
  return 0;
}

int
__libc_mallopt (int param_number, int value)
{
  mstate av = &main_arena;
  int res = 1;

  if (!__malloc_initialized)
    ptmalloc_init ();
  __libc_lock_lock (av->mutex);

  LIBC_PROBE (memory_mallopt, 2, param_number, value);

  /* We must consolidate main arena before changing max_fast
     (see definition of set_max_fast).  */
  malloc_consolidate (av);

  /* Many of these helper functions take a size_t.  We do not worry
     about overflow here, because negative int values will wrap to
     very large size_t values and the helpers have sufficient range
     checking for such conversions.  Many of these helpers are also
     used by the tunables macros in arena.c.  */

  switch (param_number)
    {
    case M_MXFAST:
      res = do_set_mxfast (value);
      break;

    case M_TRIM_THRESHOLD:
      res = do_set_trim_threshold (value);
      break;

    case M_TOP_PAD:
      res = do_set_top_pad (value);
      break;

    case M_MMAP_THRESHOLD:
      res = do_set_mmap_threshold (value);
      break;

    case M_MMAP_MAX:
      res = do_set_mmaps_max (value);
      break;

    case M_CHECK_ACTION:
      res = do_set_mallopt_check (value);
      break;

    case M_PERTURB:
      res = do_set_perturb_byte (value);
      break;

    case M_ARENA_TEST:
      if (value > 0)
	res = do_set_arena_test (value);
      break;

    case M_ARENA_MAX:
      if (value > 0)
	res = do_set_arena_max (value);
      break;
    }
  __libc_lock_unlock (av->mutex);
  return res;
}
libc_hidden_def (__libc_mallopt)


/*
   -------------------- Alternative MORECORE functions --------------------
 */


/*
   General Requirements for MORECORE.

   The MORECORE function must have the following properties:

   If MORECORE_CONTIGUOUS is false:

 * MORECORE must allocate in multiples of pagesize. It will
      only be called with arguments that are multiples of pagesize.

 * MORECORE(0) must return an address that is at least
      MALLOC_ALIGNMENT aligned. (Page-aligning always suffices.)

   else (i.e. If MORECORE_CONTIGUOUS is true):

 * Consecutive calls to MORECORE with positive arguments
      return increasing addresses, indicating that space has been
      contiguously extended.

 * MORECORE need not allocate in multiples of pagesize.
      Calls to MORECORE need not have args of multiples of pagesize.

 * MORECORE need not page-align.

   In either case:

 * MORECORE may allocate more memory than requested. (Or even less,
      but this will generally result in a malloc failure.)

 * MORECORE must not allocate memory when given argument zero, but
      instead return one past the end address of memory from previous
      nonzero call. This malloc does NOT call MORECORE(0)
      until at least one call with positive arguments is made, so
      the initial value returned is not important.

 * Even though consecutive calls to MORECORE need not return contiguous
      addresses, it must be OK for malloc'ed chunks to span multiple
      regions in those cases where they do happen to be contiguous.

 * MORECORE need not handle negative arguments -- it may instead
      just return MORECORE_FAILURE when given negative arguments.
      Negative arguments are always multiples of pagesize. MORECORE
      must not misinterpret negative args as large positive unsigned
      args. You can suppress all such calls from even occurring by defining
      MORECORE_CANNOT_TRIM,

   There is some variation across systems about the type of the
   argument to sbrk/MORECORE. If size_t is unsigned, then it cannot
   actually be size_t, because sbrk supports negative args, so it is
   normally the signed type of the same width as size_t (sometimes
   declared as "intptr_t", and sometimes "ptrdiff_t").  It doesn't much
   matter though. Internally, we use "long" as arguments, which should
   work across all reasonable possibilities.

   Additionally, if MORECORE ever returns failure for a positive
   request, then mmap is used as a noncontiguous system allocator. This
   is a useful backup strategy for systems with holes in address spaces
   -- in this case sbrk cannot contiguously expand the heap, but mmap
   may be able to map noncontiguous space.

   If you'd like mmap to ALWAYS be used, you can define MORECORE to be
   a function that always returns MORECORE_FAILURE.

   If you are using this malloc with something other than sbrk (or its
   emulation) to supply memory regions, you probably want to set
   MORECORE_CONTIGUOUS as false.  As an example, here is a custom
   allocator kindly contributed for pre-OSX macOS.  It uses virtually
   but not necessarily physically contiguous non-paged memory (locked
   in, present and won't get swapped out).  You can use it by
   uncommenting this section, adding some #includes, and setting up the
   appropriate defines above:

 *#define MORECORE osMoreCore
 *#define MORECORE_CONTIGUOUS 0

   There is also a shutdown routine that should somehow be called for
   cleanup upon program exit.

 *#define MAX_POOL_ENTRIES 100
 *#define MINIMUM_MORECORE_SIZE  (64 * 1024)
   static int next_os_pool;
   void *our_os_pools[MAX_POOL_ENTRIES];

   void *osMoreCore(int size)
   {
    void *ptr = 0;
    static void *sbrk_top = 0;

    if (size > 0)
    {
      if (size < MINIMUM_MORECORE_SIZE)
         size = MINIMUM_MORECORE_SIZE;
      if (CurrentExecutionLevel() == kTaskLevel)
         ptr = PoolAllocateResident(size + RM_PAGE_SIZE, 0);
      if (ptr == 0)
      {
        return (void *) MORECORE_FAILURE;
      }
      // save ptrs so they can be freed during cleanup
      our_os_pools[next_os_pool] = ptr;
      next_os_pool++;
      ptr = (void *) ((((unsigned long) ptr) + RM_PAGE_MASK) & ~RM_PAGE_MASK);
      sbrk_top = (char *) ptr + size;
      return ptr;
    }
    else if (size < 0)
    {
      // we don't currently support shrink behavior
      return (void *) MORECORE_FAILURE;
    }
    else
    {
      return sbrk_top;
    }
   }

   // cleanup any allocated memory pools
   // called as last thing before shutting down driver

   void osCleanupMem(void)
   {
    void **ptr;

    for (ptr = our_os_pools; ptr < &our_os_pools[MAX_POOL_ENTRIES]; ptr++)
      if (*ptr)
      {
         PoolDeallocate(*ptr);
 * ptr = 0;
      }
   }

 */


/* Helper code.  */

extern char **__libc_argv attribute_hidden;

static void
malloc_printerr (const char *str)
{
#if IS_IN (libc)
  __libc_message (do_abort, "%s\n", str);
#else
  __libc_fatal (str);
#endif
  __builtin_unreachable ();
}

#if IS_IN (libc)
/* We need a wrapper function for one of the additions of POSIX.  */
int
__posix_memalign (void **memptr, size_t alignment, size_t size)
{
  void *mem;

  if (!__malloc_initialized)
    ptmalloc_init ();

  /* Test whether the SIZE argument is valid.  It must be a power of
     two multiple of sizeof (void *).  */
  if (alignment % sizeof (void *) != 0
      || !powerof2 (alignment / sizeof (void *))
      || alignment == 0)
    return EINVAL;


  void *address = RETURN_ADDRESS (0);
  mem = _mid_memalign (alignment, size, address);

  if (mem != NULL)
    {
      *memptr = mem;
      return 0;
    }

  return ENOMEM;
}
weak_alias (__posix_memalign, posix_memalign)
#endif


int
__malloc_info (int options, FILE *fp)
{
  /* For now, at least.  */
  if (options != 0)
    return EINVAL;

  int n = 0;
  size_t total_nblocks = 0;
  size_t total_nfastblocks = 0;
  size_t total_avail = 0;
  size_t total_fastavail = 0;
  size_t total_system = 0;
  size_t total_max_system = 0;
  size_t total_aspace = 0;
  size_t total_aspace_mprotect = 0;



  if (!__malloc_initialized)
    ptmalloc_init ();

  fputs ("<malloc version=\"1\">\n", fp);

  /* Iterate over all arenas currently in use.  */
  mstate ar_ptr = &main_arena;
  do
    {
      fprintf (fp, "<heap nr=\"%d\">\n<sizes>\n", n++);

      size_t nblocks = 0;
      size_t nfastblocks = 0;
      size_t avail = 0;
      size_t fastavail = 0;
      struct
      {
	size_t from;
	size_t to;
	size_t total;
	size_t count;
      } sizes[NFASTBINS + NBINS - 1];
#define nsizes (sizeof (sizes) / sizeof (sizes[0]))

      __libc_lock_lock (ar_ptr->mutex);

      /* Account for top chunk.  The top-most available chunk is
	 treated specially and is never in any bin. See "initial_top"
	 comments.  */
      avail = chunksize (ar_ptr->top);
      nblocks = 1;  /* Top always exists.  */

      for (size_t i = 0; i < NFASTBINS; ++i)
	{
	  mchunkptr p = fastbin (ar_ptr, i);
	  if (p != NULL)
	    {
	      size_t nthissize = 0;
	      size_t thissize = chunksize (p);

	      while (p != NULL)
		{
		  if (__glibc_unlikely (misaligned_chunk (p)))
		    malloc_printerr ("__malloc_info(): "
				     "unaligned fastbin chunk detected");
		  ++nthissize;
		  p = REVEAL_PTR (p->fd);
		}

	      fastavail += nthissize * thissize;
	      nfastblocks += nthissize;
	      sizes[i].from = thissize - (MALLOC_ALIGNMENT - 1);
	      sizes[i].to = thissize;
	      sizes[i].count = nthissize;
	    }
	  else
	    sizes[i].from = sizes[i].to = sizes[i].count = 0;

	  sizes[i].total = sizes[i].count * sizes[i].to;
	}


      mbinptr bin;
      struct malloc_chunk *r;

      for (size_t i = 1; i < NBINS; ++i)
	{
	  bin = bin_at (ar_ptr, i);
	  r = bin->fd;
	  sizes[NFASTBINS - 1 + i].from = ~((size_t) 0);
	  sizes[NFASTBINS - 1 + i].to = sizes[NFASTBINS - 1 + i].total
					  = sizes[NFASTBINS - 1 + i].count = 0;

	  if (r != NULL)
	    while (r != bin)
	      {
		size_t r_size = chunksize_nomask (r);
		++sizes[NFASTBINS - 1 + i].count;
		sizes[NFASTBINS - 1 + i].total += r_size;
		sizes[NFASTBINS - 1 + i].from
		  = MIN (sizes[NFASTBINS - 1 + i].from, r_size);
		sizes[NFASTBINS - 1 + i].to = MAX (sizes[NFASTBINS - 1 + i].to,
						   r_size);

		r = r->fd;
	      }

	  if (sizes[NFASTBINS - 1 + i].count == 0)
	    sizes[NFASTBINS - 1 + i].from = 0;
	  nblocks += sizes[NFASTBINS - 1 + i].count;
	  avail += sizes[NFASTBINS - 1 + i].total;
	}

      size_t heap_size = 0;
      size_t heap_mprotect_size = 0;
      size_t heap_count = 0;
      if (ar_ptr != &main_arena)
	{
	  /* Iterate over the arena heaps from back to front.  */
	  heap_info *heap = heap_for_ptr (top (ar_ptr));
	  do
	    {
	      heap_size += heap->size;
	      heap_mprotect_size += heap->mprotect_size;
	      heap = heap->prev;
	      ++heap_count;
	    }
	  while (heap != NULL);
	}

      __libc_lock_unlock (ar_ptr->mutex);

      total_nfastblocks += nfastblocks;
      total_fastavail += fastavail;

      total_nblocks += nblocks;
      total_avail += avail;

      for (size_t i = 0; i < nsizes; ++i)
	if (sizes[i].count != 0 && i != NFASTBINS)
	  fprintf (fp, "\
  <size from=\"%zu\" to=\"%zu\" total=\"%zu\" count=\"%zu\"/>\n",
		   sizes[i].from, sizes[i].to, sizes[i].total, sizes[i].count);

      if (sizes[NFASTBINS].count != 0)
	fprintf (fp, "\
  <unsorted from=\"%zu\" to=\"%zu\" total=\"%zu\" count=\"%zu\"/>\n",
		 sizes[NFASTBINS].from, sizes[NFASTBINS].to,
		 sizes[NFASTBINS].total, sizes[NFASTBINS].count);

      total_system += ar_ptr->system_mem;
      total_max_system += ar_ptr->max_system_mem;

      fprintf (fp,
	       "</sizes>\n<total type=\"fast\" count=\"%zu\" size=\"%zu\"/>\n"
	       "<total type=\"rest\" count=\"%zu\" size=\"%zu\"/>\n"
	       "<system type=\"current\" size=\"%zu\"/>\n"
	       "<system type=\"max\" size=\"%zu\"/>\n",
	       nfastblocks, fastavail, nblocks, avail,
	       ar_ptr->system_mem, ar_ptr->max_system_mem);

      if (ar_ptr != &main_arena)
	{
	  fprintf (fp,
		   "<aspace type=\"total\" size=\"%zu\"/>\n"
		   "<aspace type=\"mprotect\" size=\"%zu\"/>\n"
		   "<aspace type=\"subheaps\" size=\"%zu\"/>\n",
		   heap_size, heap_mprotect_size, heap_count);
	  total_aspace += heap_size;
	  total_aspace_mprotect += heap_mprotect_size;
	}
      else
	{
	  fprintf (fp,
		   "<aspace type=\"total\" size=\"%zu\"/>\n"
		   "<aspace type=\"mprotect\" size=\"%zu\"/>\n",
		   ar_ptr->system_mem, ar_ptr->system_mem);
	  total_aspace += ar_ptr->system_mem;
	  total_aspace_mprotect += ar_ptr->system_mem;
	}

      fputs ("</heap>\n", fp);
      ar_ptr = ar_ptr->next;
    }
  while (ar_ptr != &main_arena);

  fprintf (fp,
	   "<total type=\"fast\" count=\"%zu\" size=\"%zu\"/>\n"
	   "<total type=\"rest\" count=\"%zu\" size=\"%zu\"/>\n"
	   "<total type=\"mmap\" count=\"%d\" size=\"%zu\"/>\n"
	   "<system type=\"current\" size=\"%zu\"/>\n"
	   "<system type=\"max\" size=\"%zu\"/>\n"
	   "<aspace type=\"total\" size=\"%zu\"/>\n"
	   "<aspace type=\"mprotect\" size=\"%zu\"/>\n"
	   "</malloc>\n",
	   total_nfastblocks, total_fastavail, total_nblocks, total_avail,
	   mp_.n_mmaps, mp_.mmapped_mem,
	   total_system, total_max_system,
	   total_aspace, total_aspace_mprotect);

  return 0;
}
#if IS_IN (libc)
weak_alias (__malloc_info, malloc_info)

strong_alias (__libc_calloc, __calloc) weak_alias (__libc_calloc, calloc)
strong_alias (__libc_free, __free) strong_alias (__libc_free, free)
strong_alias (__libc_malloc, __malloc) strong_alias (__libc_malloc, malloc)
strong_alias (__libc_memalign, __memalign)
weak_alias (__libc_memalign, memalign)
strong_alias (__libc_realloc, __realloc) strong_alias (__libc_realloc, realloc)
strong_alias (__libc_valloc, __valloc) weak_alias (__libc_valloc, valloc)
strong_alias (__libc_pvalloc, __pvalloc) weak_alias (__libc_pvalloc, pvalloc)
strong_alias (__libc_mallinfo, __mallinfo)
weak_alias (__libc_mallinfo, mallinfo)
strong_alias (__libc_mallinfo2, __mallinfo2)
weak_alias (__libc_mallinfo2, mallinfo2)
strong_alias (__libc_mallopt, __mallopt) weak_alias (__libc_mallopt, mallopt)

weak_alias (__malloc_stats, malloc_stats)
weak_alias (__malloc_usable_size, malloc_usable_size)
weak_alias (__malloc_trim, malloc_trim)
#endif

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_26)
compat_symbol (libc, __libc_free, cfree, GLIBC_2_0);
#endif

/* ------------------------------------------------------------
   History:

   [see ftp://g.oswego.edu/pub/misc/malloc.c for the history of dlmalloc]

 */
/*
 * Local variables:
 * c-basic-offset: 2
 * End:
 */
