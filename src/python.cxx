
#include "globals.hxx"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>
#include <memory>

#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <fcntl.h>
#include <linux/netlink.h>


struct syscall_ent_t {
	PyObject *po_value;
	PyObject *po_name;
};

static syscall_ent_t g_syscall_ent[] = {
#define X(s, argc, r, p) { NULL, PyString_FromString(#s) },
#include "syscallent.h"
#undef X
};

struct signal_ent_t {
	const char * const name;
	PyObject *po_value;
	PyObject *po_name;
};

static signal_ent_t g_signal_ent[] = {
#define X(s) { #s, NULL, PyString_FromString(#s) },
#include "signalent.h"
#undef X
};

static inline PyObject *py_incref(PyObject *po)
{
	Py_INCREF(po);
	return po;
}

#define None_obj (Py_INCREF(Py_None), Py_None)

static void py_print_err(void)
{
	PyErr_Print();
}

#define SHOOK_EVENT_ENUM \
	SHOOK_EVENT_DECL(SYSCALL) \
	SHOOK_EVENT_DECL(SIGNAL) \
	SHOOK_EVENT_DECL(PROCESS) \
	SHOOK_EVENT_DECL(FINISH) \
	SHOOK_EVENT_DECL(EXIT)

enum {
#define SHOOK_EVENT_DECL(x) SHOOK_EVENT_##x,
	SHOOK_EVENT_ENUM
#undef SHOOK_EVENT_DECL
	SHOOK_EVENT_MAX
};

static std::vector<pyobj_t> g_observers[SHOOK_EVENT_MAX];

static PyObject *shook_py_register(PyObject *self, PyObject* args)
{
	if (PyTuple_GET_SIZE(args) < 2) {
		PyErr_SetString(PyExc_RuntimeError, "at lease one callable");
		return NULL;
	}
	unsigned int which = PyInt_AsLong(PyTuple_GET_ITEM(args, 0));
	if (which >= SHOOK_EVENT_MAX) {
		PyErr_SetString(PyExc_RuntimeError, "Invalid index");
		return NULL;
	}

	if (g_observers[which].size() > 0) {
		PyErr_SetString(PyExc_RuntimeError, "Observer exists");
		return NULL;
	}

	for (int i = 1; i < PyTuple_GET_SIZE(args); ++i) {
		PyObject *observer = PyTuple_GET_ITEM(args, i);
		if (!PyCallable_Check(observer)) {
			PyErr_SetString(PyExc_RuntimeError, "Observer is not callable");
			g_observers[which].clear();
			return NULL;
		}
		g_observers[which].push_back(pyobj_t(py_incref(observer)));
	}

	Py_RETURN_NONE;
}

static PyObject *shook_py_set_gdb(PyObject *self, PyObject *args)
{
	unsigned int pid;
	if (!PyArg_ParseTuple(args, "i", &pid)) {
		return NULL;
	}

	shook_set_gdb(pid);
	Py_RETURN_NONE;
}

static PyObject *shook_py_resume(PyObject *self, PyObject *args)
{
	unsigned int pid;
	if (!PyArg_ParseTuple(args, "i", &pid)) {
		return NULL;
	}

	if (shook_resume(pid) == 0) {
		Py_RETURN_NONE;
	} else {
		return NULL;
	}
}

static PyObject *shook_py_peek_path(PyObject *self, PyObject *args)
{
	unsigned int pid;
	unsigned int length = PATH_MAX;
	long addr;

	if (!PyArg_ParseTuple(args, "il|I", &pid, &addr, &length)) {
		return NULL;
	}

	if (length > PATH_MAX) {
		length = PATH_MAX;
	}

	char buff[PATH_MAX + 1];
	int err = vm_peek_str(pid, buff, addr, length);
	if (err < 0) {
		return NULL;
	}
	buff[length] = '\0';
	return PyString_FromString(buff);
}

static PyObject *pystr_from_in_addr(struct in_addr ia)
{
	uint8_t *p = (uint8_t *)&ia;
	char buff[80];
	sprintf(buff, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return PyString_FromString(buff);
}

static PyObject *pystr_from_in6_addr(const struct in6_addr *ia)
{
	char buff[128];
	inet_ntop(AF_INET6, ia, buff, sizeof(*ia));
	return PyString_FromString(buff);
}

static PyObject *shook_py_peek_sockaddr(PyObject *self, PyObject *args)
{
	unsigned int pid;
	long addr;
	unsigned int salen;

	if (!PyArg_ParseTuple(args, "ili", &pid, &addr, &salen)) {
		return NULL;
	}

	if (salen > sizeof(struct sockaddr_storage)) {
		return NULL;
	}

	struct sockaddr_storage ss;
	int err = vm_peek_mem(pid, &ss, addr, salen);
	if (err < 0) {
		return NULL;
	}
	if (ss.ss_family == AF_UNIX) {
		struct sockaddr_un *sun = (struct sockaddr_un *)&ss;
		PyObject *po_ret = PyTuple_New(2);
		PyTuple_SET_ITEM(po_ret, 0, PyInt_FromLong(ss.ss_family));
		PyTuple_SET_ITEM(po_ret, 1, PyString_FromString(sun->sun_path));
		return po_ret;
	} else if (ss.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		PyObject *po_ret = PyTuple_New(3);
		PyTuple_SET_ITEM(po_ret, 0, PyInt_FromLong(ss.ss_family));
		PyTuple_SET_ITEM(po_ret, 1, pystr_from_in_addr(sin->sin_addr));
		PyTuple_SET_ITEM(po_ret, 2, PyInt_FromLong(ntohs(sin->sin_port)));
		return po_ret;
	} else if (ss.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		PyObject *po_ret = PyTuple_New(3);
		PyTuple_SET_ITEM(po_ret, 0, PyInt_FromLong(ss.ss_family));
		PyTuple_SET_ITEM(po_ret, 1, pystr_from_in6_addr(&sin6->sin6_addr));
		PyTuple_SET_ITEM(po_ret, 2, PyInt_FromLong(ntohs(sin6->sin6_port)));
		return po_ret;
	} else if (ss.ss_family == AF_NETLINK) {
		struct sockaddr_nl *sa = (struct sockaddr_nl *)&ss;
		PyObject *po_ret = PyTuple_New(3);
		PyTuple_SET_ITEM(po_ret, 0, PyInt_FromLong(ss.ss_family));
		PyTuple_SET_ITEM(po_ret, 1, PyInt_FromLong(sa->nl_pid));
		PyTuple_SET_ITEM(po_ret, 2, PyInt_FromLong(sa->nl_groups));
		return po_ret;
	} else {
		PyObject *po_ret = PyTuple_New(1);
		PyTuple_SET_ITEM(po_ret, 0, PyInt_FromLong(ss.ss_family));
		return po_ret;
	}
}

static PyObject *shook_py_poke_sockaddr(PyObject *self, PyObject *args)
{
	if (PyTuple_GET_SIZE(args) < 5) {
		return NULL;
	}

	int pid = PyInt_AsLong(PyTuple_GET_ITEM(args, 0));
	long sa_addr = PyInt_AsLong(PyTuple_GET_ITEM(args, 1));
	socklen_t slen = PyInt_AsLong(PyTuple_GET_ITEM(args, 2));
	int af = PyInt_AsLong(PyTuple_GET_ITEM(args, 3));

	if (af == AF_INET) {
		if (PyTuple_GET_SIZE(args) != 6) {
			return NULL;
		}
		const char *ip_str = PyString_AsString(PyTuple_GET_ITEM(args, 4));
		int port = PyInt_AsLong(PyTuple_GET_ITEM(args, 5));

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr(ip_str);
		sin.sin_port = htons(port);

		socklen_t poke_len = sizeof sin;
		if (poke_len > slen) {
			poke_len = slen;
		}

		slen = sizeof sin;
		vm_poke_mem(pid, &sin, sa_addr, poke_len);
		
	} else {
		/* TODO */
		assert(0);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *shook_py_poke_sockaddr2(PyObject *self, PyObject *args)
{
	if (PyTuple_GET_SIZE(args) < 5) {
		return NULL;
	}

	int pid = PyInt_AsLong(PyTuple_GET_ITEM(args, 0));
	long sa_addr = PyInt_AsLong(PyTuple_GET_ITEM(args, 1));
	long slen_addr = PyInt_AsLong(PyTuple_GET_ITEM(args, 2));
	int af = PyInt_AsLong(PyTuple_GET_ITEM(args, 3));
	socklen_t slen;
	int err = vm_peek_mem(pid, &slen, slen_addr, sizeof(slen));
	if (err < 0) {
		assert(0);
		return NULL;
	}

	if (af == AF_INET) {
		if (PyTuple_GET_SIZE(args) != 6) {
			return NULL;
		}
		const char *ip_str = PyString_AsString(PyTuple_GET_ITEM(args, 4));
		int port = PyInt_AsLong(PyTuple_GET_ITEM(args, 5));

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr(ip_str);
		sin.sin_port = htons(port);

		socklen_t poke_len = sizeof sin;
		if (poke_len > slen) {
			poke_len = slen;
		}

		slen = sizeof sin;
		vm_poke_mem(pid, &sin, sa_addr, poke_len);
		vm_poke_mem(pid, &slen, slen_addr, sizeof(slen));
		
	} else {
		TODO_assert(0);
		return NULL;
	}

	Py_RETURN_NONE;
}

template <typename T>
static PyObject *pyobj_from_native(const T &t);

template <typename T>
static bool pyobj_to_native(T &t, PyObject *po);

template <>
PyObject *pyobj_from_native(const uint32_t &t)
{
	return PyInt_FromLong(t);
}

template <>
bool pyobj_to_native(uint32_t &t, PyObject *po)
{
	t = PyInt_AsLong(po);
	return true;
}

template <>
PyObject *pyobj_from_native(const uint64_t &t)
{
	return PyLong_FromUnsignedLong(t);
}

template <>
bool pyobj_to_native(uint64_t &t, PyObject *po)
{
	t = PyLong_AsUnsignedLong(po);
	return true;
}

template <>
PyObject *pyobj_from_native(const struct iovec &t)
{
	PyObject *po_tuple = PyTuple_New(2);
	PyTuple_SET_ITEM(po_tuple, 0, PyInt_FromLong(long(t.iov_base)));
	PyTuple_SET_ITEM(po_tuple, 1, PyInt_FromLong(t.iov_len));
	return po_tuple;
}

template <>
bool pyobj_to_native(struct iovec &t, PyObject *po)
{
	return PyArg_ParseTuple(po, "ll", &t.iov_base, &t.iov_len);
}

template <>
PyObject *pyobj_from_native(const struct msghdr &mh)
{
	PyObject *po_tuple = PyTuple_New(7);
	PyTuple_SET_ITEM(po_tuple, 0, PyInt_FromLong(long(mh.msg_name)));
	PyTuple_SET_ITEM(po_tuple, 1, PyInt_FromLong(mh.msg_namelen));
	PyTuple_SET_ITEM(po_tuple, 2, PyInt_FromLong((long)mh.msg_iov));
	PyTuple_SET_ITEM(po_tuple, 3, PyInt_FromLong(mh.msg_iovlen));
	PyTuple_SET_ITEM(po_tuple, 4, PyInt_FromLong((long)mh.msg_control));
	PyTuple_SET_ITEM(po_tuple, 5, PyInt_FromLong(mh.msg_controllen));
	PyTuple_SET_ITEM(po_tuple, 6, PyInt_FromLong(mh.msg_flags));
	return po_tuple;
}

template <>
bool pyobj_to_native(struct msghdr &t, PyObject *po)
{
	long val = PyInt_AsLong(PyTuple_GET_ITEM(po, 0));
	t.msg_name = (void *)val;
	val = PyInt_AsLong(PyTuple_GET_ITEM(po, 1));
	t.msg_namelen = val;
	val = PyInt_AsLong(PyTuple_GET_ITEM(po, 2));
	t.msg_iov = (struct iovec *)val;
	val = PyInt_AsLong(PyTuple_GET_ITEM(po, 3));
	t.msg_iovlen = val;
	val = PyInt_AsLong(PyTuple_GET_ITEM(po, 4));
	t.msg_control = (struct iovec *)val;
	val = PyInt_AsLong(PyTuple_GET_ITEM(po, 5));
	t.msg_controllen = val;
	val = PyInt_AsLong(PyTuple_GET_ITEM(po, 6));
	t.msg_flags = val;
	return true;
}

template <>
PyObject *pyobj_from_native(const struct mmsghdr &mmh)
{
	PyObject *po_tuple = PyTuple_New(2);
	PyTuple_SET_ITEM(po_tuple, 0, pyobj_from_native(mmh.msg_hdr));
	PyTuple_SET_ITEM(po_tuple, 1, PyInt_FromLong(mmh.msg_len));
	return po_tuple;
}

template <>
bool pyobj_to_native(struct mmsghdr &t, PyObject *po)
{
	return pyobj_to_native(t.msg_hdr, PyTuple_GET_ITEM(po, 0)) &&
		pyobj_to_native(t.msg_len, PyTuple_GET_ITEM(po, 1));
}

template <>
PyObject *pyobj_from_native(const struct pollfd &t)
{
	PyObject *po_tuple = PyTuple_New(3);
	PyTuple_SET_ITEM(po_tuple, 0, PyInt_FromLong(t.fd));
	PyTuple_SET_ITEM(po_tuple, 1, PyInt_FromLong(t.events));
	PyTuple_SET_ITEM(po_tuple, 2, PyInt_FromLong(t.revents));
	return po_tuple;
}

template <>
bool pyobj_to_native(struct pollfd &t, PyObject *po)
{
	return PyArg_ParseTuple(po, "iHH", &t.fd, &t.events, &t.revents);
}

template <>
PyObject *pyobj_from_native(const struct epoll_event &t)
{
	PyObject *po_tuple = PyTuple_New(2);
	PyTuple_SET_ITEM(po_tuple, 0, PyInt_FromLong(t.events));
	PyTuple_SET_ITEM(po_tuple, 1, PyInt_FromLong(t.data.u64));
	return po_tuple;
}

template <>
bool pyobj_to_native(struct epoll_event &t, PyObject *po)
{
	return PyArg_ParseTuple(po, "Il", &t.events, &t.data.u64);
}

template <>
PyObject *pyobj_from_native(const struct timezone &t)
{
	PyObject *po_tuple = PyTuple_New(2);
	PyTuple_SET_ITEM(po_tuple, 0, PyInt_FromLong(t.tz_minuteswest));
	PyTuple_SET_ITEM(po_tuple, 1, PyInt_FromLong(t.tz_dsttime));
	return po_tuple;
}

template <>
bool pyobj_to_native(struct timezone &t, PyObject *po)
{
	return PyArg_ParseTuple(po, "ii", &t.tz_minuteswest, &t.tz_dsttime);
}

template <>
PyObject *pyobj_from_native(const struct timeval &t)
{
	PyObject *po_tuple = PyTuple_New(2);
	PyTuple_SET_ITEM(po_tuple, 0, PyInt_FromLong(t.tv_sec));
	PyTuple_SET_ITEM(po_tuple, 1, PyInt_FromLong(t.tv_usec));
	return po_tuple;
}

template <>
bool pyobj_to_native(struct timeval &t, PyObject *po)
{
	return PyArg_ParseTuple(po, "ll", &t.tv_sec, &t.tv_usec);
}

template <>
PyObject *pyobj_from_native(const struct timespec &t)
{
	PyObject *po_tuple = PyTuple_New(2);
	PyTuple_SET_ITEM(po_tuple, 0, PyInt_FromLong(t.tv_sec));
	PyTuple_SET_ITEM(po_tuple, 1, PyInt_FromLong(t.tv_nsec));
	return po_tuple;
}

template <>
bool pyobj_to_native(struct timespec &t, PyObject *po)
{
	return PyArg_ParseTuple(po, "ll", &t.tv_sec, &t.tv_nsec);
}

template <class T>
static PyObject *shook_py_peek_array(PyObject *self, PyObject *args)
{
	unsigned int pid;
	long addr;
	long count;

	if (!PyArg_ParseTuple(args, "ill", &pid, &addr, &count)) {
		return NULL;
	}

	std::unique_ptr<T []> array(new T[count]);
	int err = vm_peek_mem(pid, array.get(), addr, count * sizeof(T));
	if (err < 0) {
		return NULL;
	}

	PyObject *po_ret = PyTuple_New(count);
	for (int i = 0; i < count; ++i) {
		PyTuple_SET_ITEM(po_ret, i, pyobj_from_native(array[i]));
	}
	return po_ret;
}

template <class T>
static PyObject *shook_py_poke_array(PyObject *self, PyObject *args)
{
	if (PyTuple_GET_SIZE(args) < 2) {
		return NULL;
	}

	int pid = PyInt_AsLong(PyTuple_GET_ITEM(args, 0));
	long addr = PyInt_AsLong(PyTuple_GET_ITEM(args, 1));
	size_t count = PyTuple_GET_SIZE(args) - 2;

	std::unique_ptr<T []> array(new T[count]);
	for (size_t i = 0; i < count; ++i) {
		if (!pyobj_to_native(array[i], PyTuple_GET_ITEM(args, i + 2))) {
			return NULL;
		}
	}

	int err = vm_poke_mem(pid, array.get(), addr, count * sizeof(T));
	if (err < 0) {
		return NULL;
	}
	Py_RETURN_NONE;
}


static PyObject *shook_py_peek_data(PyObject *self, PyObject *args)
{
	unsigned int pid;
	long addr;
	long length;

	if (!PyArg_ParseTuple(args, "ill", &pid, &addr, &length)) {
		return NULL;
	}

	char buff[length];
	int err = vm_peek_mem(pid, buff, addr, length);
	if (err < 0) {
		return NULL;
	}

	return PyBytes_FromStringAndSize(buff, length);
}

static PyObject *shook_py_poke_data(PyObject *self, PyObject *args)
{
	unsigned int pid;
	unsigned long raddr;
	long length;
	const char *data;
	Py_ssize_t size;
	if (!PyArg_ParseTuple(args, "is#kl", &pid, &data, &size, &raddr, &length)) {
		return NULL;
	}
	if (size > length) {
		size = length;
	}
	if (size > 0) {
		vm_poke_mem(pid, data, raddr, size);
	}
	Py_RETURN_NONE;
}

static PyObject *shook_py_peek_datav(PyObject *self, PyObject *args)
{
	if (PyTuple_GET_SIZE(args) < 3) {
		return NULL;
	}

	int pid = PyInt_AsLong(PyTuple_GET_ITEM(args, 0));
	PyObject *peek_len_obj = PyTuple_GET_ITEM(args, 1);
	size_t peek_len = (Py_None == peek_len_obj) ? (size_t)-1 : PyInt_AsLong(peek_len_obj);
	size_t count = PyTuple_GET_SIZE(args) - 2;

	size_t total_len = 0;
	std::unique_ptr<struct iovec []> array(new struct iovec[count]);
	for (size_t i = 0; i < count; ++i) {
		if (!pyobj_to_native(array[i], PyTuple_GET_ITEM(args, i + 2))) {
			return NULL;
		}
		total_len += array[i].iov_len;
	}

	if (peek_len > total_len) {
		peek_len = total_len;
	}

	char data_buf[peek_len]; // TODO 
	ssize_t err = vm_peek_memv(pid, data_buf, peek_len, array.get(), count);
	if (err < 0) {
		return NULL;
	}

	return PyBytes_FromStringAndSize(data_buf, err);
}

static PyObject *shook_py_poke_datav(PyObject *self, PyObject *args)
{
	if (PyTuple_GET_SIZE(args) < 3) {
		return NULL;
	}

	int pid = PyInt_AsLong(PyTuple_GET_ITEM(args, 0));
	char *data_buf;
	Py_ssize_t data_len;
	if (PyString_AsStringAndSize(PyTuple_GET_ITEM(args, 1), &data_buf, &data_len) < 0) {
		return NULL;
	}
	size_t count = PyTuple_GET_SIZE(args) - 2;

	std::unique_ptr<struct iovec []> array(new struct iovec[count]);
	for (size_t i = 0; i < count; ++i) {
		if (!pyobj_to_native(array[i], PyTuple_GET_ITEM(args, i + 2))) {
			return NULL;
		}
	}

	ssize_t err = vm_poke_memv(pid, data_buf, data_len, array.get(), count);
	if (err < 0) {
		return NULL;
	}

	return PyInt_FromLong(err);
}


static PyObject *shook_py_alloc_stack(PyObject *self, PyObject *args)
{
	unsigned int pid;
	uint32_t size;
	if (!PyArg_ParseTuple(args, "iI", &pid, &size)) {
		return NULL;
	}
	long raddr = shook_alloc_stack(pid, size + 1);
	return PyInt_FromLong(raddr);
}

static PyObject *shook_py_alloc_copy(PyObject *self, PyObject *args)
{
	unsigned int pid;
	const char *data;
	Py_ssize_t size;
	if (!PyArg_ParseTuple(args, "is#", &pid, &data, &size)) {
		return NULL;
	}
	long raddr = shook_alloc_copy(pid, data, size + 1);
	return PyInt_FromLong(raddr);
}

static PyObject *shook_py_syscall_name(PyObject *self, PyObject *args)
{
	unsigned int syscall;
	if (!PyArg_ParseTuple(args, "i", &syscall)) {
		return NULL;
	}

	if (syscall >= sizeof(g_syscall_ent) / sizeof(g_syscall_ent[0])) {
		return NULL;
	}

	PyObject *po = g_syscall_ent[syscall].po_name;
	Py_INCREF(po);
	return po;
}

static PyObject *shook_py_signal_name(PyObject *self, PyObject *args)
{
	unsigned int signo;
	if (!PyArg_ParseTuple(args, "i", &signo)) {
		return NULL;
	}

	if (signo >= sizeof(g_signal_ent) / sizeof(g_signal_ent[0])) {
		return NULL;
	}

	PyObject *po = g_signal_ent[signo].po_name;
	Py_INCREF(po);
	return po;
}

static PyObject *shook_py_clock_gettime(PyObject *self, PyObject *args)
{
	unsigned int clk_id;
	if (!PyArg_ParseTuple(args, "I", &clk_id)) {
		return NULL;
	}

	if (clk_id <= CLOCK_MONOTONIC) {
		struct timespec tv;
		clock_gettime(clk_id, &tv);
		return pyobj_from_native(tv);
	}
	return NULL;
}

static PyObject *shook_py_write(PyObject *self, PyObject *args)
{
	const char *arg;
	int stream;

	if (!PyArg_ParseTuple(args, "is", &stream, &arg)) {
		return NULL;
	}

	shook_write(stream, arg);
	Py_RETURN_NONE;
}

static ya_tick_diff_t py_timer_func(ya_timer_t *timer, ya_tick_t now);
struct py_timer_t
{
	py_timer_t(uint32_t id_, PyObject *cb_, PyObject *args_) : id(id_), callback(cb_), args(args_) {
		ya_timer_init(&timer, py_timer_func);
		Py_INCREF(callback);
		Py_INCREF(args);
	}

	py_timer_t(const py_timer_t &) = delete;

	py_timer_t(py_timer_t &&o) : timer(o.timer), id(std::move(o.id)),
	callback(std::move(o.callback)), args(std::move(o.args)) {
		Py_INCREF(callback);
		Py_INCREF(args);
	}

	~py_timer_t() {
		Py_DECREF(callback);
		Py_DECREF(args);
	}

	ya_timer_t timer;
	uint32_t const id;
	PyObject * const callback;
	PyObject * const args;
};

static std::unordered_map<uint32_t, py_timer_t> g_timer_table;
static uint32_t g_next_timer_id;

static ya_tick_diff_t py_timer_func(ya_timer_t *timer, ya_tick_t now)
{
	py_timer_t *pyt = container_of(timer, py_timer_t, timer);
	PyObject *po_id = PyInt_FromLong(pyt->id);
	PyObject *po_ret = PyObject_CallFunctionObjArgs(pyt->callback, po_id, pyt->args, NULL);
	Py_DECREF(po_id);

	if (po_ret == NULL) {
		py_print_err();
		g_timer_table.erase(pyt->id);
		return -1;
	} else if (po_ret == Py_None) {
		g_timer_table.erase(pyt->id);
		return -1;
	} else {
		assert(PyInt_Check(po_ret));
		long milliseconds = PyInt_AsLong(po_ret);
		assert(milliseconds >= 0);
		return milliseconds;
	}
	Py_DECREF(po_ret);
}

static PyObject *shook_py_set_timer(PyObject *self, PyObject *args)
{
	PyObject *callback, *cb_args = NULL;
	int milli_seconds;
	if (!PyArg_ParseTuple(args, "iO|O", &milli_seconds, &callback, &cb_args)) {
		return NULL;
	}

	if (!PyCallable_Check(callback)) {
		PyErr_SetString(PyExc_RuntimeError, "Observer is not callable");
		return NULL;
	}

	if (!cb_args) {
		cb_args = py_incref(Py_None);
	}

	uint32_t id = g_next_timer_id;
	for ( ; g_timer_table.find(id) != g_timer_table.end(); ++id) { ; }

	auto it = g_timer_table.emplace(id, py_timer_t(id, callback, cb_args));
	shook_set_timer(&it.first->second.timer, milli_seconds);
	Py_DECREF(callback);
	Py_DECREF(cb_args);

	PyObject *po_ret = PyInt_FromLong(it.first->second.id);
	return po_ret;
}

static PyObject *shook_py_backtrace(PyObject *self, PyObject *args)
{
	int pid;
	unsigned int depth = 0;
	if (!PyArg_ParseTuple(args, "i|I", &pid, &depth)) {
		return NULL;
	}

	std::vector<stackframe_t> stacks;
	shook_backtrace(stacks, pid, depth);

	PyObject *po_ret = PyTuple_New(stacks.size());
	int i = 0;
	for (auto &stack: stacks) {
		PyObject *s = PyTuple_New(3);
		PyTuple_SET_ITEM(s, 0, PyInt_FromLong(stack.ip));
		PyTuple_SET_ITEM(s, 1, PyInt_FromLong(stack.offset));
		PyTuple_SET_ITEM(s, 2, PyString_FromString(stack.symbol.c_str()));
		PyTuple_SET_ITEM(po_ret, i++, s);
	}
	return po_ret;
}


static PyObject *shook_py_cancel_timer(PyObject *self, PyObject *args)
{
	uint32_t id;
	if (!PyArg_ParseTuple(args, "I", &id)) {
		return NULL;
	}

	auto it = g_timer_table.find(id);
	if (it == g_timer_table.end()) {
		return NULL;
	}
	shook_cancel_timer(&it->second.timer);
	Py_RETURN_NONE;
}

static PyMethodDef pymod_methods[] = {
	{ "register", shook_py_register, METH_VARARGS,
		R"EOF(register(event, handler, ...)
Register event handlers)EOF" },
	{ "set_timer", shook_py_set_timer, METH_VARARGS,
		R"EOF(set_timer(milliseconds, timer, data) -> timer_id
Return the timer id)EOF" },
	{ "cancel_timer", shook_py_cancel_timer, METH_VARARGS,
		R"EOF(cancel_timer(timer_id)
Cancel a timer)EOF" },
	{ "write", shook_py_write, METH_VARARGS,
		R"EOF(write(stream, string)
Write string to shook output.)EOF" },
	{ "backtrace", shook_py_backtrace, METH_VARARGS,
		R"EOF(backtrace(pid [, depth]) -> (stackframe, ...)
Return the tracee's stack frames)EOF" },
	{ "set_gdb", shook_py_set_gdb, METH_VARARGS,
		"Run gdb on the pid" },
	{ "alloc_stack", shook_py_alloc_stack, METH_VARARGS,
		R"EOF(alloc_stack(pid, size) -> addr
Allocated space in tracee's stack, and return the address)EOF" },
	{ "alloc_copy", shook_py_alloc_copy, METH_VARARGS,
		R"EOF(alloc_copy(pid, data) -> addr
Allocated space in tracee's stack, copy the data into it and return the address)EOF" },
	{ "resume", shook_py_resume, METH_VARARGS,
		"Resume process" },
	{ "syscall_name", shook_py_syscall_name, METH_VARARGS,
		"Return syscall name" },
	{ "signal_name", shook_py_signal_name, METH_VARARGS,
		"Return signal name" },
	{ "clock_gettime", shook_py_clock_gettime, METH_VARARGS,
		R"EOF(clock_gettime(clk_id) -> timespec
Return signal name)EOF" },
	{ "peek_path", shook_py_peek_path, METH_VARARGS,
		"Read path from tracee" },
#define PEEK_POKE_ARRAY(type, name) \
	{ "peek_" name, shook_py_peek_array<type>, METH_VARARGS, "Read " name " array from tracee" }, \
	{ "poke_" name, shook_py_poke_array<type>, METH_VARARGS, "Write " name " array to tracee" },

	PEEK_POKE_ARRAY(uint32_t, "uint32")
	PEEK_POKE_ARRAY(uint64_t, "uint64")
	PEEK_POKE_ARRAY(struct timezone, "timezone")
	PEEK_POKE_ARRAY(struct timeval, "timeval")
	PEEK_POKE_ARRAY(struct timespec, "timespec")
	PEEK_POKE_ARRAY(struct iovec, "iovec")
	PEEK_POKE_ARRAY(struct msghdr, "msghdr")
	PEEK_POKE_ARRAY(struct mmsghdr, "mmsghdr")
	PEEK_POKE_ARRAY(struct pollfd, "pollfd")
	PEEK_POKE_ARRAY(struct epoll_event, "epoll_event")

	{ "peek_data", shook_py_peek_data, METH_VARARGS,
		R"EOF(peek_data(pid, addr, len) -> data
Read data from tracee)EOF" },
	{ "poke_data", shook_py_poke_data, METH_VARARGS,
		R"EOF(poke_data(pid, data, addr, len)
Write data to tracee)EOF" },

	{ "peek_datav", shook_py_peek_datav, METH_VARARGS,
		R"EOF(peek_datav(pid, total | None, (addr, len), ...) -> data
Read data from tracee)EOF" },
	{ "poke_datav", shook_py_poke_datav, METH_VARARGS,
		R"EOF(poke_datav(pid, data, (addr, len), ...)
Write data to tracee)EOF" },

	{ "peek_sockaddr", shook_py_peek_sockaddr, METH_VARARGS,
		R"EOF(peek_sockaddr(pid, addr, slen) -> tuple
Read sockaddr from tracee)EOF" },
	{ "poke_sockaddr", shook_py_poke_sockaddr, METH_VARARGS,
		R"EOF(poke_sockaddr(pid, addr, len, af, ...)
Write sockaddr to tracee)EOF" },
	{ "poke_sockaddr2", shook_py_poke_sockaddr2, METH_VARARGS,
		R"EOF(poke_sockaddr2(pid, addr, plen, af, ...)
Write sockaddr to tracee, unlike to poke_sockaddr, plen is an address)EOF" },
	{NULL,              NULL}           /* sentinel */
};


static const char init_script[] = R"EOF(
import sys

class ShookFile(object):
	def __init__(self, stream):
		self.stream = stream
		self.buff = None
	def close(self):
		return None
	def isatty(self):
		# TODO
		return False
	def writelines(self, iterable):
		for line in iterable:
			self.write(line)
	def write(self, s):
		shook.write(self.stream, s)
	def flush(self):
		pass
		#shoo.flush(self.stream)

sys.stdout = ShookFile(1)
sys.stderr = ShookFile(2)
)EOF";

#define MODULE_NAME "shook"
#ifdef IS_PY3K
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	MODULE_NAME,
	NULL,
	-1,
	pymod_methods,
	NULL,
	NULL,
	NULL,
	NULL,
};

PyMODINIT_FUNC init_module (void);
PyMODINIT_FUNC init_module (void)
{
	return PyModule_Create(&moduledef);
}
#endif

int py_init(const char *pymod_name,
		int script_argc, char **script_argv)
{
#ifdef IS_PY3K
	PyImport_AppendInittab(MODULE_NAME, init_module);
#endif

	Py_Initialize();

	PyObject *mod_this;
#ifdef IS_PY3K
	mod_this = PyImport_ImportModule(MODULE_NAME);
#else
	mod_this = Py_InitModule(MODULE_NAME, pymod_methods);
#endif
	assert(mod_this);

	PyObject *mm = PyImport_AddModule("__main__");
	Py_INCREF(mod_this);
	int result = PyModule_AddObject(mm, pymod_name, mod_this);
	if (result < 0) {
		Py_DECREF(mod_this);
		return result;
	}

	result = PyRun_SimpleString(init_script);
	if (result < 0) {
		return -1;
	}

#define SHOOK_EVENT_DECL(x) PyModule_AddIntConstant(mod_this, "EVENT_"#x, SHOOK_EVENT_##x);
	SHOOK_EVENT_ENUM
#undef SHOOK_EVENT_DECL

#define SHOOK_ACTION_DECL(x) PyModule_AddIntConstant(mod_this, "ACTION_" #x, SHOOK_ACTION_##x);
	SHOOK_ACTION_ENUM
#undef SHOOK_ACTION_DECL

#define SHOOK_PROCESS_DECL(x) PyModule_AddIntConstant(mod_this, "PROCESS_" #x, SHOOK_PROCESS_##x);
	SHOOK_PROCESS_ENUM
#undef SHOOK_PROCESS_DECL

	for (size_t i = 0; i < sizeof(g_syscall_ent) / sizeof(g_syscall_ent[0]); ++i) {
		char symbol[80];
		snprintf(symbol, sizeof symbol, "SYS_%s", g_syscall_name[i]);
		PyObject *po = PyInt_FromLong(i);
		assert(po);
		g_syscall_ent[i].po_value = po;
		PyModule_AddObject(mod_this, symbol, po);
	}

	for (size_t i = 0; i < sizeof(g_signal_ent) / sizeof(g_signal_ent[0]); ++i) {
		char symbol[80];
		snprintf(symbol, sizeof symbol, "SIG%s", g_signal_ent[i].name);
		PyObject *po = PyInt_FromLong(i);
		assert(po);
		g_signal_ent[i].po_value = po;
		PyModule_AddObject(mod_this, symbol, po);
	}

#define ADD_INT_PYOBJECT(x) \
	PyModule_AddObject(mod_this, #x, PyInt_FromLong(x))

	ADD_INT_PYOBJECT(EPOLL_CTL_ADD);
	ADD_INT_PYOBJECT(EPOLL_CTL_MOD);
	ADD_INT_PYOBJECT(EPOLL_CTL_DEL);

	ADD_INT_PYOBJECT(SOCK_NONBLOCK);
	ADD_INT_PYOBJECT(SOCK_CLOEXEC);

	ADD_INT_PYOBJECT(CLOCK_REALTIME);
	ADD_INT_PYOBJECT(CLOCK_MONOTONIC);

	ADD_INT_PYOBJECT(AT_FDCWD);
	ADD_INT_PYOBJECT(AT_SYMLINK_FOLLOW);
	ADD_INT_PYOBJECT(AT_EMPTY_PATH);

#ifdef IS_PY3K
	{
		std::vector<wchar_t *> _argv(script_argc);
		for (int i = 0; i < script_argc; i++) {
			wchar_t* arg = Py_DecodeLocale(script_argv[i], NULL);
			_argv[i] = arg;
		}
		PySys_SetArgvEx(script_argc, _argv.data(), 0);
		for (int i = 0; i < script_argc; i++) {
			PyMem_RawFree(_argv[i]);
		}
	}
#else
	PySys_SetArgvEx(script_argc, script_argv, 0);
#endif
	{
		FILE *fp = fopen(script_argv[0], "r");
		if (fp == NULL) {
			return -1;
		}
		int err = PyRun_SimpleFile(fp, script_argv[0]);
		fclose(fp);
		return -err;
	}
}

static PyObject *create_signal_args(pid_t pid, context_t &ctx)
{
	PyObject *po_args = PyTuple_New(2);
	PyTuple_SET_ITEM(po_args, 0, PyInt_FromLong(pid));
	PyTuple_SET_ITEM(po_args, 1, PyInt_FromLong(ctx.signo));
	return po_args;
}

int shook_py_emit_enter_signal(bool abort_on_error, pid_t pid, context_t &ctx)
{
	int action = SHOOK_ACTION_NONE;
	auto &observers = g_observers[SHOOK_EVENT_SIGNAL];
	for (size_t i = ctx.signal_depth; i < observers.size(); ++i) {
		if (ctx.last_args == nullptr) {
			ctx.last_args = create_signal_args(pid, ctx);
		}

		pyobj_t po_ret(PyObject_Call(observers[i], ctx.last_args, NULL));
		if (!po_ret) {
			py_print_err();
			if (abort_on_error) {
				abort();
			}
		} else if (po_ret == Py_None) {
		} else if (!PyTuple_Check(po_ret)) {
			py_print_err();
		} else {
			size_t len = PyTuple_GET_SIZE((PyObject *)po_ret);
			if (len == 0) {
				py_print_err();
				continue;
			}
			action = PyInt_AsLong(PyTuple_GET_ITEM((PyObject *)po_ret, 0));
			if (action == SHOOK_ACTION_BYPASS) {
				TODO_assert(len == 1);
				break;
			} else if (action == SHOOK_ACTION_REDIRECT) {
				TODO_assert(len == 2);
				ctx.last_args = PyTuple_GET_ITEM((PyObject *)po_ret, 1);
				ctx.modified = true;
				action = SHOOK_ACTION_NONE;
			} else if (action == SHOOK_ACTION_GDB || action == SHOOK_ACTION_DETACH) {
				TODO_assert(len == 1);
				break;
			} else if (action == SHOOK_ACTION_SUSPEND) {
				TODO_assert(len == 1);
				return action;
			} else {
			}

		}
	}
	ctx.last_args = nullptr;
	return action;
}

static PyObject *create_syscall_args(pid_t pid, context_t &ctx)
{
	PyObject *po_args = PyTuple_New(3 + ctx.argc);
	PyTuple_SET_ITEM(po_args, 0, PyInt_FromLong(pid));
	PyTuple_SET_ITEM(po_args, 1, py_incref(Py_None));
	PyTuple_SET_ITEM(po_args, 2, py_incref(g_syscall_ent[ctx.scno].po_value));
	for (unsigned int i = 0; i < ctx.argc; ++i) {
		PyTuple_SET_ITEM(po_args, 3 + i, PyInt_FromLong(ctx.args[i]));
	}
	return po_args;
}

int shook_py_emit_enter_syscall(bool abort_on_error, pid_t pid, context_t &ctx)
{
	int action = SHOOK_ACTION_NONE;
	auto &observers = g_observers[SHOOK_EVENT_SYSCALL];
	size_t si;
	for (si = ctx.stack.size(); si < observers.size(); ++si) {
		if (ctx.last_args == nullptr) {
			ctx.last_args = create_syscall_args(pid, ctx); 
		}
		pyobj_t po_ret(PyObject_Call(observers[si], ctx.last_args, NULL));
		if (po_ret == NULL) {
			py_print_err();
			if (abort_on_error) {
				abort();
			}
			ctx.stack.push_back(ctx.last_args);
		} else if (po_ret == Py_None) {
			ctx.stack.push_back(ctx.last_args);
		} else if (!PyTuple_Check(po_ret)) {
			// TODO report
			ctx.stack.push_back(ctx.last_args);
		} else {
			size_t len = PyTuple_GET_SIZE((PyObject *)po_ret);
			if (len == 0) {
				ctx.stack.push_back(ctx.last_args);
				continue;
			}
			PyObject *po_action = PyTuple_GET_ITEM((PyObject *)po_ret, 0);
			action = PyInt_AsLong(po_action);
			if (action == SHOOK_ACTION_GDB || action == SHOOK_ACTION_DETACH) {
				return action;
			} else if (action == SHOOK_ACTION_SUSPEND) {
				ctx.stack.push_back(ctx.last_args);
				return action;
			} else if (action == SHOOK_ACTION_BYPASS) {
				TODO_assert(len == 2);
				ctx.retval = PyInt_AsLong(PyTuple_GET_ITEM((PyObject *)po_ret, 1));
				break;
			} else if (action == SHOOK_ACTION_REDIRECT) {
				ctx.stack.push_back(ctx.last_args);

				PyObject *new_args = PyTuple_New(1 + len);
				PyTuple_SET_ITEM(new_args, 0, py_incref(PyTuple_GET_ITEM((PyObject *)ctx.last_args, 0)));
				PyTuple_SET_ITEM(new_args, 1, py_incref(Py_None));
				for (size_t ai = 1; ai < len; ++ai) {
					PyTuple_SET_ITEM(new_args, ai + 1, py_incref(PyTuple_GET_ITEM((PyObject *)po_ret, ai)));
				}
				ctx.last_args = new_args;
				ctx.modified = true;
				action = SHOOK_ACTION_NONE;
			} else {
				TODO_assert(0);
				action = SHOOK_ACTION_NONE;
			}
		}
	}
	if (si == observers.size()) {
		if (ctx.modified) {
			assert(!!ctx.last_args);
			size_t len = PyTuple_GET_SIZE((PyObject *)ctx.last_args);
			assert(len >= 3);
			ctx.scno = PyInt_AsLong(PyTuple_GET_ITEM((PyObject *)ctx.last_args, 2));
			ctx.argc = len - 3;
			for (size_t argc = 0; argc < ctx.argc; ++argc) {
				ctx.args[argc] = PyInt_AsLong(PyTuple_GET_ITEM((PyObject *)ctx.last_args, argc + 3));
			}
		}
	}
	ctx.last_args = nullptr;
	return action;
}

int shook_py_emit_leave_syscall(bool abort_on_error, pid_t pid, context_t &ctx)
{
	int action = SHOOK_ACTION_NONE;
	auto &observers = g_observers[SHOOK_EVENT_SYSCALL];
	while (!ctx.stack.empty()) {
		if (ctx.last_retval == nullptr) {
			ctx.last_retval = PyInt_FromLong(ctx.retval);
		}

		pyobj_t po_args = ctx.stack.back();
		ctx.stack.pop_back();

		Py_DECREF(PyTuple_GET_ITEM((PyObject *)po_args, 1));
		PyTuple_SET_ITEM((PyObject *)po_args, 1, py_incref(ctx.last_retval));

		pyobj_t po_ret(PyObject_Call(observers[ctx.stack.size()], po_args, NULL));
		if (po_ret == nullptr) {
			py_print_err();
			if (abort_on_error) {
				abort();
			}
		} else if (po_ret == Py_None) {
		} else if (!PyTuple_Check(po_ret)) {
			// TODO report
		} else {
			size_t len = PyTuple_GET_SIZE((PyObject *)po_ret);
			if (len == 0) {
				// TODO report
				continue;
			}
			PyObject *po_action = PyTuple_GET_ITEM((PyObject *)po_ret, 0);
			action = PyInt_AsLong(po_action);
			if (action == SHOOK_ACTION_GDB || action == SHOOK_ACTION_DETACH) {
			} else if (action == SHOOK_ACTION_KILL) {
			} else if (action == SHOOK_ACTION_SUSPEND) {
				break;
			} else if (action == SHOOK_ACTION_RETURN) {
				TODO_assert(len == 2);
				ctx.last_retval = py_incref(PyTuple_GET_ITEM((PyObject *)po_ret, 1));
				ctx.modified = true;
				action = SHOOK_ACTION_NONE;
			} else {
				TODO_assert(0);
			}
		}
	}
	if (ctx.stack.empty()) {
	       	if (ctx.modified && ctx.last_retval) {
			ctx.retval = PyInt_AsLong(ctx.last_retval);
		}
		ctx.last_retval = nullptr;
	}
	return action;
}


#define CALL_OBSERVER(observer, ...) do { \
	PyObject *ret = PyObject_CallFunctionObjArgs(observer, __VA_ARGS__); \
	if (ret == NULL) { \
		py_print_err(); \
		if (abort_on_error) { \
			abort(); \
		} \
	} else { \
		Py_DECREF(ret); \
	} \
} while (0)

int shook_py_emit_process(bool abort_on_error, pid_t pid, unsigned int pt, int ppid)
{
	if (g_observers[SHOOK_EVENT_PROCESS].empty()) {
		return 0;
	}

	PyObject *po_pid = PyInt_FromLong(pid);
	PyObject *po_pt = PyInt_FromLong(pt);
	PyObject *po_ppid = PyInt_FromLong(ppid);
	
	for (auto observer: g_observers[SHOOK_EVENT_PROCESS]) {
		CALL_OBSERVER(observer, po_pid, po_pt, po_ppid, NULL);
	}

	Py_DECREF(po_ppid);
	Py_DECREF(po_pt);
	Py_DECREF(po_pid);
	return 0;
}

int shook_py_emit_finish(bool abort_on_error)
{
	for (auto rit = g_observers[SHOOK_EVENT_FINISH].rbegin(); rit != g_observers[SHOOK_EVENT_FINISH].rend(); ++rit) {
		CALL_OBSERVER(*rit, NULL);
	}
	return 0;
}

