// MIT License Copyright(c) 2017, 2020, 2021 Hiroshi Shimamoto
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

static inline void ldatetime(char *dt, int sz)
{
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	if (!tmp)
		strcpy(dt, "-");
	else
		strftime(dt, sz, "%F %T", tmp);
}

#define logf(...) \
	do { \
		char dt[80]; \
		ldatetime(dt, sizeof(dt)); \
		fprintf(stderr, "%s [%d] ", dt, getpid()); \
		fprintf(stderr, __VA_ARGS__); \
		fflush(stderr); \
	} while (0)

void get_duration(char *buf, int n, struct timeval *prev)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	int duration = now.tv_sec - prev->tv_sec;
	if (duration < 600) {
		int ms = (now.tv_usec - prev->tv_usec) / 1000;
		if (ms < 0) {
			ms += 1000;
			duration++;
		}
		snprintf(buf, n, "%d.%03ds", duration, ms);
	} else if (duration < 3600) {
		snprintf(buf, n, "%dm", duration / 60);
	} else if (duration < 12 * 3600) {
		int h = duration / 3600;
		int m = (duration / 60) % 60;
		snprintf(buf, n, "%dh %dm", h, m);
	} else {
		snprintf(buf, n, "%dh", duration / 3600);
	}
}

#define BUFSZ	(65536)
const int defport = 8888;
const int bufsz = BUFSZ;
static char buf[BUFSZ];

static int listensocket(int port)
{
	struct sockaddr_in addr;
	int s, one = 1;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		goto bad;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto bad;
	if (listen(s, 5) < 0)
		goto bad;

	return s;
bad:
	close(s);
	return -1;
}

static void enable_tcpkeepalive(int s, int idle, int cnt, int intvl)
{
	int val = 1;
	socklen_t len = sizeof(val);

	// enable
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &val, len);
	// set params
	val = idle;
	setsockopt(s, SOL_TCP, TCP_KEEPIDLE, &val, len);
	val = cnt;
	setsockopt(s, SOL_TCP, TCP_KEEPCNT, &val, len);
	val = intvl;
	setsockopt(s, SOL_TCP, TCP_KEEPINTVL, &val, len);
}

static int child_connect(int s, const char *host, const char *port)
{
	struct addrinfo hints, *res;
	int r;

	r = socket(AF_INET, SOCK_STREAM, 0);
	if (r < 0)
		return -1;

	enable_tcpkeepalive(r, 120, 5, 5);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port, &hints, &res) != 0)
		return -1;
	if (connect(r, res->ai_addr, res->ai_addrlen) < 0)
		return -1; /* TODO: freeaddrinfo(res) */
	freeaddrinfo(res);

	return r;
}

static void child_readwrite(int s, int r)
{
	fd_set fds;
	int max;
	int ret;

	max = (r > s) ? r : s;
	max++;

	for (;;) {
		struct timeval tv;
		FD_ZERO(&fds);
		FD_SET(s, &fds);
		FD_SET(r, &fds);
		tv.tv_sec = 3600;
		tv.tv_usec = 0;
		ret = select(max, &fds, NULL, NULL, &tv);
		if (ret < 0)
			return;
		if (ret == 0) {
			logf("nothing happens in hour, disconnect\n");
			return;
		}
		if (FD_ISSET(s, &fds)) {
			ret = read(s, buf, bufsz);
			if (ret <= 0)
				return;
			if (write(r, buf, ret) <= 0)
				return;
		}
		if (FD_ISSET(r, &fds)) {
			ret = read(r, buf, bufsz);
			if (ret <= 0)
				return;
			if (write(s, buf, ret) <= 0)
				return;
		}
	}
}

static void child_work(char *from, int s)
{
	char *proto, *crlf2;
	char *host, *port;
	int ret;
	int len;
	int r;
	struct timeval tv_start;
	char duration[32];
	char target[256];
	int goodrequest = 0;

	gettimeofday(&tv_start, NULL);
	snprintf(target, 256, "UNKNOWN");

	/* if it does not look HTTP CONNECT request, just ignore */
	len = 0;
	while (len < bufsz) {
		ret = read(s, buf + len, bufsz - len);
		if (ret <= 0)
			goto out;
		len += ret;
		if (strstr(buf, "\r\n\r\n") != NULL)
			break;
	}
	if (strncmp(buf, "CONNECT ", 8))
		goto out;
	proto = strstr(buf + 8, " HTTP/1");
	if (!proto)
		goto out;
	crlf2 = strstr(proto, "\r\n\r\n");
	if (!crlf2)
		goto out;

	/* get host:port */
	host = buf + 8;
	port = host;
	while (port < proto) {
		if (*port == ':')
			goto hostok;
		port++;
	}
	goto bad;
hostok:
	goodrequest = 1;
	*port++ = '\0'; /* clear ':' */
	*proto = '\0';
	snprintf(target, 256, "%s:%s", host, port);
	r = child_connect(s, host, port);
	if (r < 0)
		goto bad;
	logf("established %s %s\n", from, target);
	/* connect ok 56789 123456789 123 */
	write(s, "HTTP/1.0 200 CONNECT OK\r\n\r\n", 27);
	/* write rest */
	crlf2 += 4;
	ret -= crlf2 - &buf[0];
	if (ret > 0)
		write(r, crlf2, ret);

	child_readwrite(s, r);
	goto out;
bad:
	if (goodrequest) {
		/*        0123456789 123456789 12 3 4 5 6 */
		write(s, "HTTP/1.0 404 Not Found\r\n\r\n", 26);
	} else {
		/*        0123456789 123456789 1234 5 6 7 8 */
		write(s, "HTTP/1.0 400 Bad Request\r\n\r\n", 28);
	}
out:
	get_duration(duration, 32, &tv_start);
	logf("close %s %s [%s]\n", from, target, duration);
}

static void accept_and_run(int s)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int cli;
	pid_t pid;

	cli = accept(s, (struct sockaddr *)&addr, &len);
	if (cli == -1) {
		if (errno == EINTR)
			return;
		exit(1);
	}

	/* ok, fork it */
	pid = fork();
	if (pid) {
		/* no need client side socket */
		close(cli);
		return;
	}

	/* no need accept socket */
	close(s);

	enable_tcpkeepalive(cli, 120, 5, 5);
	child_work(inet_ntoa(addr.sin_addr), cli);
	_exit(0);
}

int main(int argc, char **argv)
{
	int port = defport;
	int s;

	if (argc >= 2)
		port = atoi(argv[1]);

	/* don't care about child */
	signal(SIGCHLD, SIG_IGN);

	s = listensocket(port);
	if (s < 0)
		exit(1);

	/* accept loop */
	for (;;)
		accept_and_run(s);

	return 0;
}
