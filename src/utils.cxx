
#include "utils.h"
#include <stdint.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/param.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <algorithm>

unsigned long get_pagesize(void)
{
        static unsigned long pagesize;

        if (!pagesize)
                pagesize = sysconf(_SC_PAGESIZE);
        return pagesize;
}

#define SIZEOF_LONG 8
ssize_t vm_poke_mem(pid_t pid, const void *laddr, long raddr, size_t len)
{
	const struct iovec local = {
		.iov_base = (void *)laddr,
		.iov_len = len
	};
	const struct iovec remote = {
		.iov_base = (void *) raddr,
		.iov_len = len
	};
	return process_vm_writev(pid, &local, 1, &remote, 1, 0);
}

ssize_t vm_peek_mem(pid_t pid, void *laddr, long raddr, size_t len)
{
	const struct iovec local = {
		.iov_base = laddr,
		.iov_len = len
	};
	const struct iovec remote = {
		.iov_base = (void *) raddr,
		.iov_len = len
	};
	return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

ssize_t vm_poke_memv(pid_t pid, const void *laddr, size_t llen, const struct iovec *riov, size_t riovcnt)
{
	const struct iovec local = {
		.iov_base = (void *)laddr,
		.iov_len = llen
	};
	return process_vm_writev(pid, &local, 1, riov, riovcnt, 0);
}

ssize_t vm_peek_memv(pid_t pid, void *laddr, size_t llen, const struct iovec *riov, size_t riovcnt)
{
	const struct iovec local = {
		.iov_base = laddr,
		.iov_len = llen
	};
	return process_vm_readv(pid, &local, 1, riov, riovcnt, 0);
}

/*
 * Read string ended by NUL from tracee
 *
 * Returns < 0 on error
 * Returns < len if NUL is seen
 * else if NUL was not seen in len of bytes
 */
ssize_t vm_peek_str(pid_t pid, void *laddr, unsigned long addr, unsigned long len)
{
	const size_t page_size = get_pagesize();
	const size_t page_mask = page_size - 1;
	char *dst = (char *)laddr;

	while (len > 0) {
		unsigned long chunk_len = std::min(len, page_size);
		unsigned long end_in_page = (addr + chunk_len) & page_mask;
		if (chunk_len > end_in_page) {
			/* read at most one page each time, otherwise
			 * it could failed with EFAULT */
			chunk_len -= end_in_page;
		}

		ssize_t ret = vm_peek_mem(pid, dst, addr, chunk_len);
		if (ret < 0) {
			return -errno;
		}

		char *eos = (char *)memchr(dst, '\0', ret);
		if (!eos) {
			addr += ret;
			dst += ret;
			len -= ret;
		} else {
			return eos - (char *)laddr;
		}
	}
	return len;
}

