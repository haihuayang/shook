
#ifndef __utils__h__
#define __utils__h__

#include <unistd.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned long get_pagesize(void);
ssize_t vm_poke_mem(pid_t pid, const void *laddr, long raddr, size_t len);
ssize_t vm_peek_mem(pid_t pid, void *laddr, long raddr, size_t len);
ssize_t vm_poke_memv(pid_t pid, const void *laddr, size_t llen, const struct iovec *riov, size_t riovcnt);
ssize_t vm_peek_memv(pid_t pid, void *laddr, size_t llen, const struct iovec *riov, size_t riovcnt);

ssize_t vm_peek_str(pid_t pid, void *laddr, unsigned long addr, unsigned long len);

#ifdef __cplusplus
}
#endif

#endif /* __utils__h__ */

