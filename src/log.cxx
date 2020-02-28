
#include "globals.hxx"
#include <fcntl.h>
#include <stdarg.h>

static const char * const level_name[] = {
	"Fatal",
	"Error",
	"Warn",
	"Info",
	"Debug",
	"Verb",
};

unsigned int loglevel = LOG_INFO;
static int logfd = 2;
static char g_logbuf[8192];
static int g_loglen = 0;

void shook_log(int level, const char *fmt, ...)
{
	char *p = g_logbuf, *end = p + sizeof(g_logbuf) - 1; // 1 byte for \n
	struct tm tm_now;
	struct timeval tv_now;
	gettimeofday(&tv_now, NULL);
	time_t t = tv_now.tv_sec;
	localtime_r(&t, &tm_now);
	int l = strftime(p, end - p, "%T", &tm_now);
	if (l == 0) {
		goto truncated;
	}
	p += l;
	l = snprintf(p, end - p, ":%06d %s ", (unsigned int)tv_now.tv_usec, level_name[level]);
	if (p + l >= end) {
		goto truncated;
	}
	p += l;

	va_list va;
	va_start(va, fmt);
	l = vsnprintf(p, end - p, fmt, va);
	assert(l >= 0);
	if (p + l >= end) {
		goto truncated;
	}
	p += l;

output:
	*p++ = '\n';
	write(logfd, g_logbuf, p - g_logbuf);
	return;

truncated:
	p = end - 2;
	*p++ = '>';
	*p++ = '>';
	goto output;
}

bool shook_output_init(const char *file, unsigned int level)
{
	loglevel = level;
	if (file) {
		int fd = open(file, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
				S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (fd < 0) {
			return false;
		}
		logfd = fd;
	}
	return true;
}

void shook_write(int stream, const char *str)
{
	const char *eol = strrchr(str, '\n');
	if (eol) {
		if (g_loglen > 0) {
			write(logfd, g_logbuf, g_loglen);
			g_loglen = 0;
		}
		write(logfd, str, eol + 1 - str);
		size_t len = strlen(eol + 1);
		if (len < sizeof(g_logbuf)) {
			strcpy(g_logbuf, eol + 1);
			g_loglen = len;
		} else {
			write(logfd, eol + 1, len);
		}
	} else {
		size_t len = strlen(str);
		if (len + g_loglen < sizeof(g_logbuf)) {
			strcpy(g_logbuf + g_loglen, str);
			g_loglen += len;
		} else {
			write(logfd, g_logbuf, g_loglen);
			g_loglen = 0;
			write(logfd, str, len);
		}
	}
}


