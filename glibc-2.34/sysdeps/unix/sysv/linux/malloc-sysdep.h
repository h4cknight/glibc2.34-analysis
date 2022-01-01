/* System-specific malloc support functions.  Linux version.
   Copyright (C) 2012-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <fcntl.h>
#include <not-cancel.h>

/* The Linux kernel overcommits address space by default and if there is not
   enough memory available, it uses various parameters to decide the process to
   kill.  It is however possible to disable or curb this overcommit behavior
   by setting the proc sysctl vm.overcommit_memory to the value '2' and with
   that, a process is only allowed to use the maximum of a pre-determined
   fraction of the total address space.  In such a case, we want to make sure
   that we are judicious with our heap usage as well, and explicitly give away
   the freed top of the heap to reduce our commit charge.  See the proc(5) man
   page to know more about overcommit behavior.

   Other than that, we also force an unmap in a secure exec.  */
static inline bool
check_may_shrink_heap (void)
{
  static int may_shrink_heap = -1;

  if (__builtin_expect (may_shrink_heap >= 0, 1))
    return may_shrink_heap;//如果初始化过这个变量，就直接返回

  may_shrink_heap = __libc_enable_secure;//好像默认为1如果__libc_enable_secure未被初始化器改变的话

  if (__builtin_expect (may_shrink_heap == 0, 1))
    {
      //0: heuristic overcommit (this is the default)  启发式的
      //1: always overcommit, never check
      //2: always check, never overcommit

      int fd = __open_nocancel ("/proc/sys/vm/overcommit_memory",
				O_RDONLY | O_CLOEXEC);
      if (fd >= 0)
	{
	  char val;
	  ssize_t n = __read_nocancel (fd, &val, 1);
	  may_shrink_heap = n > 0 && val == '2';//如果overcommit_memory过量使用内存为2,意味着不允许overcommit，就会将值设置为1,否则为0
	  __close_nocancel_nostatus (fd);
	}
    }

  return may_shrink_heap;
}

#define HAVE_MREMAP 1
