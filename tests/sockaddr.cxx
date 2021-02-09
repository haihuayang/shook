
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <sstream>

static std::vector<std::string> split(const char *str, char sep)
{
	std::vector<std::string> result;
	std::string comp;
	std::istringstream strstr(str);
	while (std::getline(strstr, comp, sep)) {
		result.push_back(comp);
	}
	return result;
}

static int parse_sockaddr(struct sockaddr_storage *ss, const char *str)
{
	std::vector<std::string> comps = split(str, '/');
	if (comps.empty()) {
		return -EINVAL;
	}

	if (comps[0] == "inet") {
		if (comps.size() != 3) {
			return -EINVAL;
		}
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;
		sin->sin_family = AF_INET;
		if (!inet_pton(AF_INET, comps[1].c_str(), &sin->sin_addr)) {
			return -EINVAL;
		}
		char *end;
		unsigned long val = strtoul(comps[2].c_str(), &end, 0);
		if (*end) {
			return -EINVAL;
		}
		sin->sin_port = htons(val);
		return sizeof(*sin);
	} else if (comps[0] == "inet6") {
		if (comps.size() < 3) {
			return -EINVAL;
		}
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		sin6->sin6_family = AF_INET6;
		if (!inet_pton(AF_INET6, comps[1].c_str(), &sin6->sin6_addr)) {
			return -EINVAL;
		}
		char *end;
		unsigned long val = strtoul(comps[2].c_str(), &end, 0);
		if (*end) {
			return -EINVAL;
		}
		sin6->sin6_port = htons(val);
		if (comps.size() >= 4) {
			val = strtoul(comps[3].c_str(), &end, 0);
			if (*end) {
				return -EINVAL;
			}
			sin6->sin6_flowinfo = val;
		}
		if (comps.size() >= 5) {
			val = strtoul(comps[4].c_str(), &end, 0);
			if (*end) {
				return -EINVAL;
			}
			sin6->sin6_scope_id = val;
		}
		if (comps.size() > 5) {
			return -EINVAL;
		}
		return sizeof(*sin6);
	} else {
		return -EINVAL;
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		return EINVAL;
	}

	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof ss);
	int ret = parse_sockaddr(&ss, argv[1]);
	if (ret < 0) {
		return -ret;
	}

	socklen_t slen = ret;
	write(9999, &ss, slen);
	write(9999, &ss, slen);
	return 0;
}

