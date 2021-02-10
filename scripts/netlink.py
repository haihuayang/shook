#!/usr/bin/env python

from __future__ import print_function
import os, sys, errno, struct, socket, random
import shook
sys.path.append(os.path.dirname(__file__)); import shook_utils


ARPHRD_ETHER		= 1
ARPHRD_LOOPBACK		= 772

RT_SCOPE_UNIVERSE	=0
RT_SCOPE_SITE		=200
RT_SCOPE_LINK		=253
RT_SCOPE_HOST		=254
RT_SCOPE_NOWHERE	=255

NLMSG_DONE		= 3
RTM_NEWLINK		= 16
RTM_GETLINK		= 18
RTM_NEWADDR		= 20
RTM_GETADDR		= 22

IFLA_UNSPEC		= 0
IFLA_ADDRESS		= 1
IFLA_BROADCAST		= 2
IFLA_IFNAME		= 3
IFLA_MTU		= 4
IFLA_LINK		= 5
IFLA_QDISC		= 6
IFLA_STATS		= 7
IFLA_COST		= 8
IFLA_PRIORITY		= 9
IFLA_MASTER		= 10
IFLA_WIRELESS		= 11
IFLA_PROTINFO		= 12
IFLA_TXQLEN		= 13
IFLA_MAP		= 14
IFLA_WEIGHT		= 15
IFLA_OPERSTATE		= 16
IFLA_LINKMODE		= 17
IFLA_LINKINFO		= 18
IFLA_NET_NS_PID		= 19
IFLA_IFALIAS		= 20
IFLA_NUM_VF		= 21
IFLA_VFINFO_LIST	= 22
IFLA_STATS64		= 23
IFLA_VF_PORTS		= 24
IFLA_PORT_SELF		= 25
IFLA_AF_SPEC		= 26
IFLA_GROUP		= 27
IFLA_NET_NS_FD		= 28
IFLA_EXT_MASK		= 29
IFLA_PROMISCUITY	= 30
IFLA_NUM_TX_QUEUES	= 31
IFLA_NUM_RX_QUEUES	= 32
IFLA_CARRIER		= 33
IFLA_PHYS_PORT_ID	= 34
IFLA_CARRIER_CHANGES	= 35
IFLA_PHYS_SWITCH_ID	= 36
IFLA_LINK_NETNSID	= 37
IFLA_PHYS_PORT_NAME	= 38
IFLA_PROTO_DOWN		= 39
IFLA_GSO_MAX_SEGS	= 40
IFLA_GSO_MAX_SIZE	= 41
IFLA_PAD		= 42
IFLA_XDP		= 43
IFLA_EVENT		= 44
IFLA_MAX		= 45

IFA_UNSPEC		= 0
IFA_ADDRESS		= 1
IFA_LOCAL		= 2
IFA_LABEL		= 3
IFA_BROADCAST		= 4
IFA_ANYCAST		= 5
IFA_CACHEINFO		= 6
IFA_MULTICAST		= 7
IFA_FLAGS		= 8

IFA_F_PERMANENT		= 0x80


class in_ifaddr:
	def __init__(self, ifa_addr, ifa_prefixlen, ifa_scope, broadcast):
		self.ifa_prefixlen, self.ifa_scope = ifa_prefixlen, ifa_scope
		self.ifa_addr, = struct.unpack('>I', socket.inet_aton(ifa_addr))
		if broadcast:
			self.ifa_broadcast = self.ifa_addr | ((1 << (32 - ifa_prefixlen)) - 1)
		else:
			self.ifa_broadcast = None

class iface:
	# only one address for now
	def __init__(self, ifname, ifi_type, ifi_index, ifi_flags, mtu, tx_queue_len, ifaddr):
		self.ifname, self.ifi_type, self.ifi_index, self.ifi_flags, self.mtu = ifname, ifi_type, ifi_index, ifi_flags, mtu
		self.tx_queue_len = tx_queue_len
		self.ifaddr = ifaddr
		if ifi_type == ARPHRD_LOOPBACK:
			self.dev_addr = self.broadcast = b'\x00' * 6
		else:
			self.dev_addr = bytes([random.randrange(0, 256) for _ in range(0, 6)])
			self.broadcast = b'\xff' * 6

def nla_put_data(attrtype, val):
	length = len(val)
	pad = ((length + 3) // 4) * 4 - length
	return struct.pack('<HH', 4 + length, attrtype) + val + b'\x00' * pad

def nla_put_bytes(attrtype, val):
	length = 4 + len(val) + 1
	output = struct.pack('<HH', length, attrtype)
	pad = ((length + 3) // 4) * 4 - length
	return output + val + b'\x00' * (pad + 1)

def nla_put_uint32(attrtype, val):
	return struct.pack('<HHI', 8, attrtype, val)

def nla_put_uint8(attrtype, val):
	return struct.pack('<HHI', 5, attrtype, val)

def nla_put_in_addr(attrtype, val):
	return struct.pack('<HH', 8, attrtype) + struct.pack('>I', val)

def pack_link(iface, retarr):
	# ifinfomsg
	retarr.append(struct.pack('<BBHIII', 0, 0, iface.ifi_type, iface.ifi_index, iface.ifi_flags, 0))
	# linux rtnl_fill_ifinfo
	retarr.append(nla_put_bytes(IFLA_IFNAME, iface.ifname))
	retarr.append(nla_put_uint32(IFLA_TXQLEN, 1))
	retarr.append(nla_put_uint8(IFLA_OPERSTATE, 6)) # IF_OPER_UP
	retarr.append(nla_put_uint8(IFLA_LINKMODE, 0))

	retarr.append(nla_put_uint32(IFLA_MTU, iface.mtu))
	retarr.append(nla_put_uint32(IFLA_GROUP, 0))
	retarr.append(nla_put_uint32(IFLA_PROMISCUITY, 0))
	retarr.append(nla_put_uint32(IFLA_NUM_TX_QUEUES, 1))

	retarr.append(nla_put_uint32(IFLA_GSO_MAX_SEGS, 0xffff))
	retarr.append(nla_put_uint32(IFLA_GSO_MAX_SIZE, 0x10000))
	retarr.append(nla_put_uint32(IFLA_NUM_RX_QUEUES, 1))
	retarr.append(nla_put_uint8(IFLA_CARRIER, 1))
	# retarr.append(nla_put_uint32(IFLA_LINK, iface.ifi_index))

	retarr.append(nla_put_bytes(IFLA_QDISC, b"noqueue"))
	retarr.append(nla_put_uint32(IFLA_CARRIER_CHANGES, 0))
	retarr.append(nla_put_uint8(IFLA_PROTO_DOWN, 0))

	# TODO IFLA_MAP
	retarr.append(nla_put_data(IFLA_ADDRESS, iface.dev_addr))
	retarr.append(nla_put_data(IFLA_BROADCAST, iface.broadcast))

	# TODO IFLA_STATS64, IFLA_STATS, IFLA_AF_SPEC


def pack_addr(iface, retarr):
	# ifaddrmsg
	ifa = iface.ifaddr
	retarr.append(struct.pack('<BBBBI', socket.AF_INET, ifa.ifa_prefixlen, IFA_F_PERMANENT,
				ifa.ifa_scope, iface.ifi_index))
	# linux inet_fill_ifaddr
	retarr.append(nla_put_in_addr(IFA_ADDRESS, ifa.ifa_addr))
	retarr.append(nla_put_in_addr(IFA_LOCAL, ifa.ifa_addr))
	retarr.append(nla_put_bytes(IFA_LABEL, iface.ifname))
	if ifa.ifa_broadcast is not None:
		retarr.append(nla_put_in_addr(IFA_BROADCAST, ifa.ifa_broadcast))
	retarr.append(nla_put_uint32(IFA_FLAGS, IFA_F_PERMANENT))
	# TODO IFA_CACHEINFO

class netlink_socket(shook_utils.FD):
	def __init__(self, ifaces):
		self.index = 0
		self.ifaces = ifaces

	def on_sendto(self, pid, retval, fd, addr, length, flags, src_addr, addrlen):
		assert retval is None
		#TODO check length == 20?
		data = shook.peek_data(pid, addr, length)
		nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack_from('<IHHII', data)
		#TODO check nlmsg_len == 20?
		assert nlmsg_type in [ RTM_GETLINK, RTM_GETADDR]

		self.index = 0
		self.nlmsg_seq = nlmsg_seq
		self.nlmsg_type = nlmsg_type
		return shook.ACTION_BYPASS, length

	def on_recvmsg(self, pid, retval, fd, msg, flags):
		assert retval is None
		iface_index = self.index

		msg_name, msg_namelen, msg_iov, msg_iovlen, _, _, msg_flags = shook.peek_msghdr(pid, msg, 1)[0]
		#print('on_recvmsg', '0x%x' % flags, msg_iov, msg_iovlen, msg_flags)
		v_msg_name = struct.pack('<HHII', socket.AF_NETLINK, 0, 0, 0)
		if msg_namelen > len(v_msg_name):
			msg_namelen = len(v_msg_name)
		shook.poke_data(pid, v_msg_name, msg_name, msg_namelen)

		if iface_index >= len(self.ifaces):
			data = struct.pack('<IHHIII', 20, 3, 2, self.nlmsg_seq, pid, 0)
		else:
			retarr = [b'\x00' * 16]
			if self.nlmsg_type == RTM_GETLINK:
				pack_link(self.ifaces[self.index], retarr)
				nlmsg_type = RTM_NEWLINK
			else:
				pack_addr(self.ifaces[self.index], retarr)
				nlmsg_type = RTM_NEWADDR
			nlmsg_length = sum([ len(x) for x in retarr ])
			retarr[0] = struct.pack('<IHHII', nlmsg_length, nlmsg_type, 2, self.nlmsg_seq, pid)
			data = b''.join(retarr)
			iface_index += 1

		iovec = shook.peek_iovec(pid, msg_iov, msg_iovlen)
		ret = shook.poke_datav(pid, data, *iovec)
		#print('shook.poke_datav', iovec, ret)
		if flags & socket.MSG_TRUNC:
			ret = len(data)
		if not (flags & socket.MSG_PEEK):
			self.index = iface_index
		return shook.ACTION_BYPASS, ret


SIOCGIFCONF	= 0x8912
SIOCGIFINDEX	= 0x8933
SIOCGIFFLAGS	= 0x8913
SIOCSIFFLAGS	= 0x8914
SIOCGIFHWADDR	= 0x8927
SIOCSIFHWADDR	= 0x8924
SIOCGIFADDR	= 0x8915
SIOCSIFADDR	= 0x8916
SIOCGIFNETMASK	= 0x891B
SIOCSIFNETMASK	= 0x891C
SIOCETHTOOL	= 0x8946

def ioctl(pid, ifaces, arg_request, arg_argp):
	def find_iface_by_name():
		data = shook.peek_data(pid, arg_argp, 16)
		ifname = data.split(b'\x00', 1)[0]
		for iface in ifaces:
			if iface.ifname == ifname:
				return iface
		return None
	def return_ifaddr(addr):
		data = nla_put_in_addr(IFA_ADDRESS, addr) + b'\x00' * 8
		shook.poke_data(pid, data, arg_argp + 16, 16)
		return shook.ACTION_BYPASS, 0

	if arg_request == SIOCGIFINDEX:
		iface = find_iface_by_name()
		if iface:
			shook.poke_uint32(pid, arg_argp + 16, iface.ifi_index)
			return shook.ACTION_BYPASS, 0
		else:
			return shook.ACTION_BYPASS, -errno.ENODEV
	elif arg_request == SIOCGIFADDR:
		iface = find_iface_by_name()
		if not iface:
			return shook.ACTION_BYPASS, -errno.ENODEV
		else:
			return return_ifaddr(iface.ifa_addr)
	# TODO SIOCGIFFLAGS, SIOCGIFHWADDR, ...
