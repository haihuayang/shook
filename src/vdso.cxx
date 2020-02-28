
#include "globals.hxx"
#include "utils.h"
#include <elf.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/mman.h>


#define INVALID_ADDR ((unsigned long)(-1))

static unsigned long get_vdso_addr_by_rsp(pid_t pid, unsigned long rsp)
{
	unsigned long base = rsp;
	unsigned long argc = ptrace(PTRACE_PEEKDATA, pid, base, NULL);
	/* skip the argv */
	base += (argc + 2) * sizeof(unsigned long);
	/* skip the environment */
	DBG("pid %d env at 0x%lx, rsp 0x%lx", pid, base, rsp);
	for (;;) {
		unsigned long env = ptrace(PTRACE_PEEKDATA, pid, base, NULL);
		if (env == INVALID_ADDR) {
			LOG(LOG_ERROR, "pid %d peek at 0x%lx, errno %d, rsp 0x%lx, argc %ld",
					pid, base, errno, rsp, argc);
			return INVALID_ADDR;
		}
		base += sizeof(long);
		if (!env) {
			break;
		}
	}
	DBG("pid %d auxv at 0x%lx, rsp 0x%lx", pid, base, rsp);
	unsigned long vdso_addr = INVALID_ADDR;
	for (;;) {
		unsigned long type = ptrace(PTRACE_PEEKDATA, pid, base, NULL);
		if (type == INVALID_ADDR) {
			LOG(LOG_ERROR, "pid %d peek at 0x%lx, errno %d, rsp 0x%lx, argc %ld",
					pid, base, errno, rsp, argc);
			return INVALID_ADDR;
		} else if (type == AT_NULL) {
			LOG(LOG_WARN, "Cannot found AT_SYSINFO_EHDR pid=%d, rsp=0x%lx", pid, rsp);
			return INVALID_ADDR;
		} else if (type == AT_SYSINFO_EHDR) {
			vdso_addr = ptrace(PTRACE_PEEKDATA, pid, base + sizeof(long), NULL);
			return vdso_addr;
		}
		base += 2 * sizeof(long);
	}
}

static unsigned long get_vdso_addr_by_proc(pid_t pid)
{
	char proc_name[32];
	snprintf(proc_name, sizeof proc_name, "/proc/%d/auxv", pid);
	int fd = open(proc_name, O_RDONLY);
	if (fd < 0) {
		LOG(LOG_ERROR, "Fail to open auxv for pid %d, errno %d",
				pid, errno);
		return INVALID_ADDR;
	}
	unsigned long key_val[2];
	unsigned long vdso_addr = INVALID_ADDR;
	for (;;) {
		ssize_t ret = read(fd, key_val, sizeof key_val);
		if (ret == 0) {
			break;
		} else if (key_val[0] == AT_SYSINFO_EHDR) {
			vdso_addr = key_val[1];
			break;
		}
	}
	close(fd);
	return vdso_addr;
}

static ssize_t poke_text(pid_t pid, unsigned long raddr, const uint8_t *laddr, size_t len)
{
	unsigned long skip = raddr & (sizeof(unsigned long) - 1);
	if (skip > 0) {
		unsigned long val = ptrace(PTRACE_PEEKDATA, pid, raddr - skip, 0);
		size_t copy_len = sizeof(unsigned long) - skip;
		if (copy_len > len) {
			copy_len = len;
		}
		memcpy((uint8_t *)&val + skip, laddr, copy_len);
		if (ptrace(PTRACE_POKEDATA, pid, raddr - skip, val) < 0) {
			return -1;
		}
		len -= copy_len;
		laddr += copy_len;
		raddr += copy_len;
	}

	for ( ; len >= sizeof(unsigned long); len -= sizeof(unsigned long)) {
		unsigned long val;
		memcpy(&val, laddr, sizeof(unsigned long));
		if (ptrace(PTRACE_POKEDATA, pid, raddr, val) < 0) {
			return -1;
		}
		raddr += sizeof(unsigned long);
		laddr += sizeof(unsigned long);
	}

	if (len > 0) {
		assert(len < sizeof(unsigned long));
		unsigned long val = ptrace(PTRACE_PEEKDATA, pid, raddr, 0);
		memcpy(&val, laddr, len);
		if (ptrace(PTRACE_POKEDATA, pid, raddr, val) < 0) {
			return -1;
		}
	}
	return 0;
}

static void set_syscall(pid_t pid, const char *name, unsigned long raddr)
{
	unsigned int scno = get_scno_by_name(name);
	if (scno == SCNO_INVALID) {
		DBG("\"%s\" is not a syscall", name);
		return;
	}

	/* TODO only x86_64 */
	uint8_t buf[] = { 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x0f,
		0x05, 0xc3, };
	memcpy(buf + 3, &scno, sizeof scno);

	/* cannot use process_vm_writev, because the address is RO */
	ssize_t ret = poke_text(pid, raddr, buf, sizeof buf);
	if (ret < 0) {
		LOG(LOG_ERROR, "Fail to rewrite syscall %s at 0x%lx",
				name, raddr);
	} else {
		DBG("success to rewrite syscall %s", name);
	}
}

/* Overwrite the virtual syscall function 
 * setting AT_SYSINFO_EHDR to 0 wont work, because glibc fallback to
 * vsyscall
 */
int shook_disable_vdso(pid_t pid, unsigned long rsp)
{
	unsigned long vdso_addr = rsp ?
		get_vdso_addr_by_rsp(pid, rsp) : get_vdso_addr_by_proc(pid);
	unsigned long page_size = get_pagesize();

	/* TODO decide elf size, now we always use 2 page */
	char *vdso_buf = (char *)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert(vdso_buf != (void *)-1);
	vm_peek_mem(pid, vdso_buf, vdso_addr, 2 * page_size);

	const Elf64_Ehdr *ehptr = (Elf64_Ehdr*)vdso_buf;
	/* TODO verify e_shoff + e_shnum * sizeof(Elf64_Shdr) <= 8k */
	const Elf64_Shdr *shptr = (Elf64_Shdr*)(vdso_buf + ehptr->e_shoff);

	/* TODO check elf header */
	const Elf64_Shdr &shstrndx = shptr[ehptr->e_shstrndx];
	/* TODO verify sh_offset + sh_size <= 8k */
	const Elf64_Shdr *sh_dynstr = nullptr;
	const Elf64_Shdr *sh_dynsym = nullptr;
	for (Elf64_Half i = 0; i < ehptr->e_shnum && (!sh_dynstr || !sh_dynsym);  ++i) {
		const auto &sh = shptr[i];
		/* TODO verify sh_name < shstrndx.sh_size */
		const char *name = vdso_buf + shstrndx.sh_offset + sh.sh_name;
		if (strcmp(name, ".dynstr") == 0) {
			sh_dynstr = &sh;
		} else if (strcmp(name, ".dynsym") == 0) {
			sh_dynsym = &sh;
		}
	}
	TODO_assert(sh_dynstr);
	TODO_assert(sh_dynsym);
	const Elf64_Sym *sym = (const Elf64_Sym *)(vdso_buf + sh_dynsym->sh_offset);
	const char *dynstr = vdso_buf + sh_dynstr->sh_offset;
	for (uint32_t i = 0; i < sh_dynsym->sh_size / sh_dynsym->sh_entsize; ++i) {
		const char *name = dynstr + sym[i].st_name;
		DBG("VDSO %s at %lu", name, sym[i].st_value);
		set_syscall(pid, name, vdso_addr + sym[i].st_value);
	} 
	return 0;
}

