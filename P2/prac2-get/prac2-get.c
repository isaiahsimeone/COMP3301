#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h> 
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <err.h>

static __dead void	usage(void);
static void		send_HTTP_request(int, char*, char*);
static void		get_and_output_HTTP_response(int);
static int		resolve_and_connect(char*, char*, int);

void
send_HTTP_request(int fd, char* file, char* host)
{
	char* requestString;
	/* 
	 * Construct HTTP request:
	 * GET / HTTP/1.0
	 * Host: hostname
	 * <blank line>
	 */
	asprintf(&requestString, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", 
	    file, host);

	/* Send our request to server */
	if(write(fd, requestString, strlen(requestString)) < 1)
		err(2, "Write error");
	free(requestString);
}

void
get_and_output_HTTP_response(int fd)
{
	char buffer[1024];
	int numBytesRead;
	int eof = 0;

	/* Repeatedly read from network fd until nothing left */
	while (eof == 0) {
		numBytesRead = read(fd, buffer, 1024);
		if(numBytesRead < 0)
			err(3, "Read error");
		else if(numBytesRead == 0)
			eof = 1;
		else 
			fwrite(buffer, sizeof(char), numBytesRead, stdout);
	}
}

__dead void
usage(void)
{

	extern char *__progname;
	fprintf(stderr, "usage: %s [-46] [-p port] host [url]\n", __progname);
	exit(1);
}

int
resolve_and_connect(char* hostname, char* port, int family)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int save_errno;
	int fd;

	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(hostname, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));
	fd = -1;
	/* Walk over the results list until we find a match */
	for (res = res0; res; res = res->ai_next)
		if (res->ai_family == family)
			break;
	/* Create a socket */
	fd = socket(family, res->ai_socktype, res->ai_protocol);
	if (fd == -1)
		cause = "socket";
	/* Bind to that socket */
	if (connect(fd, res->ai_addr, res->ai_addrlen) == -1) {
		cause = "connect";
		save_errno = errno;
		close(fd);
		errno = save_errno;
		fd = -1;
	}

	if (fd == -1)
		err(1, "%s", cause);
	freeaddrinfo(res0);

	return fd;
}

int
main(int argc, char* argv[]) 
{
	char* port = "80";
	char* hostname;
	char* url = "/"; /* We use the root of the page by default */
	int family = AF_INET; /* We use IPV4 by default */

	if (argc < 2)
		usage();

	int option;
	while ((option = getopt(argc, argv, "46p:")) != -1) {
		switch (option) {
		case '4':
			/* IPV4 */
			family = AF_INET;
			break;
		case '6':
			/* IPV6 */
			family = AF_INET6;
			break;
		case 'p':
			port = optarg;
			break;
		case ':':
			break;
		case '?':
			/* FALLTHROUGH */
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (argv[optind])
		hostname = argv[optind++];
	else 
		usage();
	

	if (argv[optind])
		url = argv[optind];

	int fd = resolve_and_connect(hostname, port, family);

	send_HTTP_request(fd, url, hostname);
	get_and_output_HTTP_response(fd);
	close(fd);
	return 0;
}