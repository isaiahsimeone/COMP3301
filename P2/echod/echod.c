#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include <event.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

/*
 * maybe useful functions. they're not static so the linker doesnt get upset.
 */
void	hexdump(const void *, size_t);
void	msginfo(const struct sockaddr_storage *, socklen_t, size_t);

__dead static void usage(void);

struct echod {
	TAILQ_ENTRY(echod)
			entry;
	struct event	ev;
};
TAILQ_HEAD(echod_list, echod);

static void
echod_recv(int fd, short revents, void *conn)
{
	/* Space for both IPV4 and IPV6 */
	struct sockaddr_storage addr;
	int addr_len = sizeof(addr);
	char buf[128];
	int sz = 0;
	/* Read the message  */
	if ((sz = recvfrom(fd, buf, sizeof(buf), 0, 
	    (struct sockaddr *)&addr, &addr_len)) == -1)
		err(1, "recvfrom");
	buf[sz] = '\0';
	/* Send the message back */
	if (sendto(fd, buf, strlen(buf), MSG_WAITALL,
	    (struct sockaddr *)&addr, addr_len) == -1)
		err(1, "sendto");
}

__dead static void
usage(void)
{
	extern char *__progname;
	fprintf(stderr,
	    "usage: %s [-46] [-l address] [-p port]\n", __progname);
	exit(1);
}

static void
echod_bind(struct echod_list *echods, sa_family_t af,
    const char *host, const char *port)
{
	int serrno = ENOTCONN;
	const char *cause = NULL;

	struct addrinfo hints, *res, *res0;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM; /* Use UDP */
	hints.ai_flags = AI_PASSIVE; /* Suitable for binding */
	/* Get the address information of the host and port given */
	int error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));

	/* Walk over the results until we find a matching family */
	for (res = res0; res; res = res->ai_next)
		if (res->ai_family == af)
			break;	
	/* Create a socket in datagram mode */
	int fd = socket(af, SOCK_DGRAM, res->ai_protocol);
	if (fd == -1)
		cause = "Socket";
	/* Bind to that socket */
	if (bind(fd, (struct sockaddr*)res->ai_addr, 
	    res->ai_addrlen) == -1)
		cause = "Bind";		
	
	struct echod* e = malloc(sizeof(struct echod));
	/* Add the fd */
	event_set(&e->ev, fd, EV_READ|EV_PERSIST, NULL, NULL);
	/* Add to the end of the queue */
	TAILQ_INSERT_TAIL(echods, e, entry);

	if (TAILQ_EMPTY(echods) || cause != NULL)
		errc(1, serrno, "host %s port %s %s", host, port, cause);
}

int
main(int argc, char *argv[])
{
	struct echod *e;
	struct echod_list echods = TAILQ_HEAD_INITIALIZER(echods);
	sa_family_t af = AF_UNSPEC;
	const char *host = "localhost";
	const char *port = "3301";
	int ch;

	while ((ch = getopt(argc, argv, "46l:p:")) != -1) {
		switch (ch) {
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
		case 'l':
			host = (strcmp(optarg, "*") == 0) ? NULL : optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	echod_bind(&echods, af, host, port); /* this works or exits */

	event_init();

	TAILQ_FOREACH(e, &echods, entry) {
		event_set(&e->ev, EVENT_FD(&e->ev), EV_READ|EV_PERSIST,
		    echod_recv, e);
		event_add(&e->ev, NULL);
	}

	event_dispatch();

	return (0);
}

void
hexdump(const void *d, size_t datalen)
{
	const uint8_t *data = d;
	size_t i, j = 0;

	for (i = 0; i < datalen; i += j) {
		printf("%4zu: ", i);
		for (j = 0; j < 16 && i+j < datalen; j++)
			printf("%02x ", data[i + j]);
		while (j++ < 16)
			printf("   ");
		printf("|");
		for (j = 0; j < 16 && i+j < datalen; j++)
			putchar(isprint(data[i + j]) ? data[i + j] : '.');
		printf("|\n");
	}
}

void
msginfo(const struct sockaddr_storage *ss, socklen_t sslen, size_t len)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int error;

	error = getnameinfo((const struct sockaddr *)ss, sslen,
	    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (error != 0) {
		warnx("msginfo: %s", gai_strerror(error));
		return;
	}

	printf("host %s port %s bytes %zu\n", hbuf, sbuf, len);
}
