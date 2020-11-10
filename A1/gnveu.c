#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

#define ETHERTYPE_IPV4	0x0800
#define ETHERTYPE_IPV6	0x86DD
#define MAX_PACKET_SZ	0x10000

struct tap {
	TAILQ_ENTRY(tap) entry;
	struct	 event ev;
	struct	 event *timeout_ev;
	char	*device_path;
	int	 vni;
	int	 server_fd;
	int	 idle_timeout;
};

struct geneve_header {
	uint8_t	 version_optlen;	/* version then options length */
	uint8_t	 control_critical_rsvd;	/* Control, critical and reserved */
	uint16_t protocol;		/* Protocol type */
	uint32_t vni_rsvd;		/* VNI followed by reserved bits */
};

struct server_ev {
	struct	event ev;
};

struct server_args {
	struct	tap_list *tap_list;
	struct	event *timeout_ev;
	int	idle_timeout;
};
TAILQ_HEAD(tap_list, tap);

static int	 count_occurrences(char *, char);
static bool	 is_numeric(char *);
static int	 connect_to_server(const char *, const char *, const char *,
		     const char *, sa_family_t);
static char	*geneve_wrap(int, char *);
static void	 reset_timer(struct event *, int);
static int	 get_ethertype(char *);
static void	 tap_device_cb(int, short, void *);
static bool	 parse_tunnel_arg(char *, char *, int *);
static void	 tap_listen(struct tap_list *, char *, int);
static void	 server_response_cb(int, short, void *);
__dead static void usage(void);
__dead static void timeout_cb(int, short, void *);

/*
 * Counts the number of times a specified character appears in
 * a specified string.
 *
 *     target:   The string to search for the character 'occurrence'
 * occurrence:   The character that is being searched for in the target
 *
 *    returns:   The number of times that occurrence appears in target
 */
static int
count_occurrences(char *target, char occurrence)
{
	int occurrences = 0;
	for (int i = 0; i < strlen(target); i++) {
		if (target[i] == occurrence)
			occurrences++;
	}
	return occurrences;
}

/*
 * Determines whether a given string is numeric (i.e. all characters 
 * in the string are digits). 
 *
 * If an empty string is specified by the input parameter, then
 * is_numeric returns false.
 *
 *   input:   The string to test numeric status.
 *
 * returns:   true iff the string is numeric, false otherwise
 */
static bool
is_numeric(char *input) 
{
	/* Check that each individual character is numeric */
	for (int i = 0; i < strlen(input); i++) {
		if (!isdigit(input[i]))
			return false; 
	}
	return true;
}

/*
 * Prints out to stderr a usage message describing to the user the
 * arguments expected by gnveu.
 * 
 * This function does not return.
 */
__dead static void
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-46d] [-l address] [-p port] -t 120\n\t"
		"-e /dev/tapX@vni\n\tserver [port]\n", __progname);
	exit(1);
} 

/*
 * This function is called back by libevent once a specified time
 * has been exceeded (i.e. idle_timeout).
 * 
 * This function does not return.
 */
__dead static void
timeout_cb(int fd, short event, void *arg)
{
	lwarnx("Idle timeout exceeded, exiting.");
	exit(0);
}

/*
 * This function shall resolve and connect to the specified hostname 
 * and port from the specified source_address and source_port (using
 * the specified IP version family (e.g. AF_INET or AF_INET6))
 *
 * This function will create one single UDP socket to the host. TCP is
 * not supported.
 * 
 *	 hostname:   The name of the host that should be connected to.
 *		     this argument can be specified as either a numeric
 *		     IP address or host name URL
 *	     port:   The port that should be connected to on the host
 * source_address:   The address that will be bound to locally (and receive
 *		     replies from the host on)
 *    source_port:   The port that will be bound to locally for replies
 *		     from the specified host.
 *	   family:   The address family that should be used when connecting
 *		     to the host, and binding locally (AF_INET or AF_INET6)
 *
 *	  returns:   A file descriptor that can be used to communicate 
 *		     with the specfied host.
 */
static int
connect_to_server(const char *hostname, const char *port,
    const char *source_address, const char *source_port, sa_family_t family)
{
	struct addrinfo hints, *res, *res0;
	struct sockaddr_in6 addr6;
	struct sockaddr_in addr4;
	int error, fd, flags;
	
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;	/* UDP */
	error = getaddrinfo(hostname, port, &hints, &res0);
	if (error != 0)
		lerrx(2, "%s", gai_strerror(error));
	fd = -1;
	/* Walk over the results list until we find a match */
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == family) 
			break;
	}
	/* Create a socket */
	fd = socket(family, res->ai_socktype, res->ai_protocol);
	if (fd == -1)
		lerr(2, "Failed to create socket");

	/* Make the descriptor non blocking */
	flags = 1;
	ioctl(fd, FIONBIO, &flags);

	if (family == AF_INET) {
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(atoi(source_port));
		if (source_address == NULL) {
			addr4.sin_addr.s_addr = INADDR_ANY;
		} else {
			addr4.sin_addr.s_addr = inet_addr(source_address);
		}
		if (bind(fd, (struct sockaddr *)&addr4, sizeof(addr4)) == -1)
			lerr(2, "Failed to bind to socket");
	} else {
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(atoi(source_port));
		if (source_address == NULL) {
			addr6.sin6_addr = in6addr_any;
		} else {
			inet_pton(AF_INET6, source_address, &addr6.sin6_addr);
		}
		if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) == -1)
			lerr(2, "Failed to bind to socket");
	}

	/* Connect to that socket */
	if (connect(fd, res->ai_addr, res->ai_addrlen) == -1) {
		close(fd);
		lerr(2, "Failed to connect to server");
	}

	freeaddrinfo(res0);
	return fd;
}

/*
 * Given an ethernet data packet, this function will generate
 * a GENEVE header before concatenating that ethernet packet to
 * the end of the GENEVE header.
 *
 * Information on the GENEVE header/GENEVE encapsulation can be 
 * found here: https://tools.ietf.org/html/draft-ietf-nvo3-geneve-16
 *
 *     vni:   The specified VNI (Virtual Network Identifier) will
 *	      be used in the generation of a GENEVE header.
 *  packet:   The ethernet data packet that will be encapsulated
 *	      within the geneve header.
 *
 * returns:   The same ethernet packet provided as an argument,
 *	      wrapped in a geneve header.
 */
static char *
geneve_wrap(int vni, char *packet)
{
	struct geneve_header g_header;
	char header[8];
	uint32_t u32;
	uint16_t u16;
	uint8_t u8;

	memset(&g_header, 0, sizeof(g_header));
	/* Set version and options length */
	g_header.version_optlen = 0;
	/* Control, Critical bits and reserved bits should be 0 */
	g_header.control_critical_rsvd = 0;
	/* Protocol - Always 0x6558 */
	g_header.protocol = htons(0x6558);
	/* VNI first 24 bits, last 8 bits rsvd */
	g_header.vni_rsvd |= htonl(vni << 8);

	/* Construct the GENEVE header */
	memset(&header, 0, 8);
	u8 = g_header.version_optlen;
	memcpy(header + 0, &u8, 1);
	u8 = g_header.control_critical_rsvd;
	memcpy(header + 1, &u8, 1);
	u16 = g_header.protocol;
	memcpy(header + 2, &u16, 2);
	u32 = g_header.vni_rsvd;
	memcpy(header + 4, &u32, 4);

	/* Copy the header (8 bytes) and then the original packet */
	char *encapsulated_packet = malloc(sizeof(char) * MAX_PACKET_SZ);
	memset(encapsulated_packet, 0, MAX_PACKET_SZ);
	memcpy(encapsulated_packet + 0, header, 8);
	memcpy(encapsulated_packet + 8, packet, MAX_PACKET_SZ - 8);

	return encapsulated_packet;
}

/*
 * Given a libevent event structure (being used for timeout event)
 * this function shall (re)set that event to the specified time
 * value.
 *
 * timeout_ev:   An event structure that is used for timeout events.
 * timeout_value:   The time value (in seconds) that the timeout
 *		    event should be set to.
 */
static void
reset_timer(struct event *timeout_ev, int timeout_value)
{
	/* Check if no timeout is specified */
	if (timeout_value == 0)
		return ;
	struct timeval tv;

	evtimer_del(timeout_ev);
	tv.tv_sec = timeout_value;
	tv.tv_usec = 0;
	evtimer_add(timeout_ev, &tv);
}

/*
 * Given an ethernet packet, this function will extract and return
 * the type of payload, (e.g IPV6 or IPV4)
 *
 *  packet:   The ethernet packet in question
 *
 * returns:   The version (ethertype) of the packet specified.
 */
static int
get_ethertype(char *packet)
{
	uint16_t ethertype = 0;

	/* Advance 12 bytes through the outer ethernet header */
	memcpy(&ethertype, packet + 12, 1);
	/* Extract the next 2 bytes (EtherType) */
	ethertype &= 0xFFFF; 
	
	return ntohs(ethertype);
}

/*
 * This function is called back by libevent upon a tap device file
 * becoming readable (i.e. data is available for reading).
 * Once data is read from the tap device, it is sent to
 * the server specified when running gnveu if applicable.
 *
 * Packets read from the tap device will be wrapped in a geneve header
 * and forwarded to the server.
 *
 *      fd:   The file descriptor of the tap device that is readable
 * revents:   The flags associated with the event that lead to the callback
 *    args:   An argument that will be cast to the type of 
 *	      tap*. This struct should be initialised with the file descriptor
 *	      of the server that packets should be sent to and libevent timing
 *	      information.
 */
static void
tap_device_cb(int fd, short revents, void *args)
{	
	struct tap *tap_device;
	char *packet, *encapsulated;
	int read_sz, server_fd;

	tap_device = (struct tap *)args;
	server_fd = tap_device->server_fd;

	packet = malloc(sizeof(char) * MAX_PACKET_SZ);
	memset(packet, 0, MAX_PACKET_SZ);

	/* Read from the tap device */
	if ((read_sz = read(fd, packet, MAX_PACKET_SZ)) == -1)
		lerr(2, "Failed to read from %s\n", tap_device->device_path);

	/* Discard non-IPV4 packet for VNI 4096 */
	if (tap_device->vni == 4096 && get_ethertype(packet) != ETHERTYPE_IPV4)
		return ;

	/* Discard non-IPV6 packet for VNI 8192 */
	if (tap_device->vni == 8192 && get_ethertype(packet) != ETHERTYPE_IPV6)
		return ;

	/* Encapsulate the packet in a GENEVE header */
	encapsulated = geneve_wrap(tap_device->vni, packet);

	/* Write the encapsulated packet to the server */
	if (send(server_fd, encapsulated, read_sz + 100, 0) == -1)
		lerr(2, "Error writing to server");

	/* Traffic has been exchanged - reset the timeout event */
	reset_timer(tap_device->timeout_ev, tap_device->idle_timeout);

	free(encapsulated);
	free(packet);
}

/*
 * Used to parse the -e argument of the gnveu program. Given
 * a string representing a -e argument, this function will attempt
 * to split it into both a device_path and a VNI.
 *
 * This function does not validate that the specified device in the
 * '-e DEVICE@VNI' format, is indeed a tap device.
 *
 *	   arg:   The -e argument that should be checked for validity
 *		  and parsed into a device_path and VNI.
 * device_path:   A pointer to the char* type that the device path
 *		  will be stored in. This argument should be allocated
 *		  and doing so is the responsibility of the caller
 *	   vni:   A pointer to an integer where the extracted VNI will
 *		  be stored.
 *
 *     returns:   True iff the -e argument was formatted validly, false
 *		  otherwise.
 */
static bool
parse_tunnel_arg(char *arg, char *device_path, int *vni)
{
	char *vni_portion;

	if (arg == NULL || strlen(arg) <= 3)
		return false;
	/* Check that there is one, and only one '@' character */
	if (count_occurrences(arg, '@') != 1)
		return false;

	strcpy(device_path, strtok(arg, "@"));
	vni_portion = strtok(NULL, "@");

	/* Check that the specified VNI is numeric and exists */
	if (vni_portion == NULL || !is_numeric(vni_portion))
		return false;
	*vni = atoi(vni_portion);
	return true;
}

/*
 * This function is used to prepare a tap device for use. Valid tap
 * devices are opened and an event is created for the event where
 * data becomes readable on a tap device.
 *
 * Tap devices are configured to be non-blocking via ioctl(). If
 * a tap device has already been opened by this function, the event
 * shall still be created, but using the file descriptor of that tap
 * device when it was opened (i.e. on a previous call to the function).
 *
 * This function allows the creation of events for multiple device-VNI
 * pairings, however, any VNI given to this function must be unique 
 * from all past and future callings.
 *
 *	  taps:   A queue (TailQ) which contains all of the tap devices
 *		  that have been initialised. If the tap device specified
 *		  by "device_path" is opened successfully, it will be added
 *		  to this queue.
 * device_path:   The path to the tap device, e.g "/dev/tapX"
 *	   vni:   The Virtual Network Identifier associated with this tap
 *		  device.
 */
static void
tap_listen(struct tap_list *taps, char *device_path, int vni)
{
	struct tap *tap_device;
	int device_fd = 0;
	int flags;
	bool device_open = false;
	
	/* See if we've already encountered this device */
	TAILQ_FOREACH(tap_device, taps, entry) {
		/* Check whether the specified device has already been opened */
		if (strcmp(tap_device->device_path, device_path) == 0) {
			device_open = true;
			/* Get the FD of the same device that is already open */
			device_fd = EVENT_FD(&tap_device->ev);
			/* Device can now be considered open */
		}
	}

	if (device_open == false) {
		/* Open the tap device for reading and writing */
		device_fd = open(device_path, O_RDWR);
		/* Configure the read/write operations to be non-blocking */
		flags = 1;
		ioctl(device_fd, FIONBIO, &flags);

		if (device_fd == -1)
			lerr(1, "Failed to open device %s", device_path);
		/* Device is now open */
	}

	tap_device = malloc(sizeof(struct tap));
	tap_device->vni = vni;
	/* Record the name of this device (for subsequent calls) */
	tap_device->device_path = malloc(sizeof(char) * strlen(device_path));
	strcpy(tap_device->device_path, device_path);
	/* Add the device file descriptor */
	event_set(&tap_device->ev, device_fd, EV_READ|EV_PERSIST,
		tap_device_cb, tap_device);

	/* Add the new tap device to the Queue */
	TAILQ_INSERT_TAIL(taps, tap_device, entry);
}

/*
 * This function is called back by libevent when the server connected
 * to (in the event) has sent data that has arrived and is readable.
 *
 * This function assumes that data received from the server is GENEVE
 * encapsulated, such that it can be redirected to the appropriate tap
 * device.
 *
 * Data received from the server shall be separated from its GENEVE 
 * header and forwarded to the corresponding tap device (based upon
 * the VNI that was contained within the GENEVE header of the received data)
 *
 *      fd:   The file descriptor of the server (bound to the
 *	      event callback) that is readable.
 * revents:   The flags associated with the vent that caused the callback 
 *	      to occur.
 *    args:   An argument that will be cast to the type of server_args*.
 *	      The struct should be initialised with a list of all open
 *	      tap devices and a pointer to the event responsible for 
 *	      timeouts, and the value that the timeout should be set to.
 */
static void
server_response_cb(int fd, short revents, void *args)
{
	struct tap *tap_device;
	struct server_args *server_args = (struct server_args *)args;
	struct tap_list *taps = server_args->tap_list;
	struct geneve_header g_header;
	char *response, *raw_packet;
	int device_fd = 0;
	int packet_sz = 0;
	int vni;

	/* Some type of traffic has been received - reset the timer */
	reset_timer(server_args->timeout_ev, server_args->idle_timeout);

	response = malloc(sizeof(char) * MAX_PACKET_SZ);
	raw_packet = malloc(sizeof(char) * MAX_PACKET_SZ);

	memset(response, 0, MAX_PACKET_SZ);
	memset(raw_packet, 0, MAX_PACKET_SZ);
	memset(&g_header, 0, sizeof(g_header));

	/* Receive the packet sent by the server */
	if ((packet_sz = recv(fd, response, MAX_PACKET_SZ, 0)) == -1)
		lerr(1, "Error reading from server");

	/* Move the received packet (less the 8 byte GENEVE header) */
	memmove(raw_packet, response + 8, MAX_PACKET_SZ - 8);
	/* Move the first 8 bytes of the packet (GENEVE header) */
	memmove(&g_header, response, 8);

	/* Get VNI from GENEVE header of the received packet */
	vni = ntohl(g_header.vni_rsvd) >> 8;

	/* Search for the tap device associated with the packet VNI */
	TAILQ_FOREACH(tap_device, taps, entry) {
		if (tap_device->vni == vni) {
			device_fd = EVENT_FD(&tap_device->ev);
			/* Write to the corresponding tap device */
			if (write(device_fd, raw_packet, packet_sz - 8) == -1)
				lerr(1, "Failed to write to tap device");
			break;
		}
	}

	free(response);
	free(raw_packet);
}

/*
 * Gnveu allows for the tunneling of multiple network connections to 
 * a server over one single UDP connection. Ethernet packets are read
 * from /dev/tap devices and tunneled to a server via the GENEVE protocol
 *
 * Tunnel entry/exit points are specified by the -e argument. Each tunnel
 * is connected to the kernel via the tap(4) device driver. Multiple
 * tap devices may be tunneled with unique Virtual Network Identifier
 * values (VNI). E.g. -e /dev/tap0@4096 -e /dev/tap0@3301 -e /dev/tap1@0
 * is valid, but -e /dev/tap0@4096 -e /dev/tap0@3301 -e /dev/tap1@3301 is
 * not (because of the duplicated 3301 VNI value.)
 *
 * gnveu will run until killed or until no traffic has been exchanged for
 * a specified period of time.
 */
int
main(int argc, char **argv) 
{
	struct tap_list taps = TAILQ_HEAD_INITIALIZER(taps);
	struct tap *tap_device;
	struct event timeout_ev;
	struct server_ev *server_event;
	struct server_args *server_args;
	struct timeval timeout_value;
	/* Default flag settings */
	sa_family_t addrfamily = AF_INET;
	bool daemonise = true;
	const char *address = NULL;
	const char *destport = "6081";
	const char *server = NULL;
	const char *source_port = "6081";
	char *device_path;
	int vni = 0;
	int idle_timeout = -1;
	int server_fd;
	char ch;
	
	while ((ch = getopt(argc, argv, "46dl:p:t:e:")) != -1) {
		switch (ch) {
		case '4':
			addrfamily = AF_INET;
			break;
		case '6':
			addrfamily = AF_INET6;
			break;
		case 'd':
			/* Daemonise */
			daemonise = false;
			break;
		case 'l':
			/* Set Local address */
			address = optarg;
			break;
		case 'p':
			/* Set local source port */
			source_port = optarg;
			break;
		case 't':
			/* Timeout - must be specified, 0 if negative */
			if (atoi(optarg) == 0 && optarg != 0)
				lerrx(1, "Invalid argument: Idle timeout (-t)");
			idle_timeout = (atoi(optarg) > 0 ? atoi(optarg) : 0);
			break;
		case 'e':
			/* Tunnel enter/exit */
			device_path = malloc(sizeof(char) * strlen(optarg));
			if (parse_tunnel_arg(optarg, device_path, &vni) == false)
				lerrx(1, "Invalid argument: Tunnel enter/exit (-e)");

			tap_listen(&taps, device_path, vni);
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	if (argc < 3)
		usage();
		/* NOTREACHED */
	/* Ensure required flags were specified */
	if (idle_timeout == -1)
		lerrx(1, "Missing argument: Idle timeout (-t)");
	if (TAILQ_EMPTY(&taps) == true)
		lerrx(1, "Missing argument: Ethernet tunnel (-e)");
	/* Get non-flag arguments */
	/* Check for mandatory host argument */
	if (argv[optind] == 0)
		usage();
		/* NOTREACHED */
	else 
		server = argv[optind];
	/* Check for optional destination port argument */
	if (argv[optind + 1] != NULL)
		destport = argv[optind + 1];
	/* If source port is not specified, then it should  
	 * be the same as the destination port */
	if (source_port == NULL)
		source_port = destport;
	/* Daemonise process */
	if (daemonise == true) {
		if (daemon(1, 1) == -1) 
			lerr(1, "Failed to daemonise");
		else
			logger_syslog(getprogname());
	}

	/* Connect to the host */
	server_fd = connect_to_server(server, destport, address,
	     source_port, addrfamily);

	timeout_value.tv_sec = idle_timeout;
	timeout_value.tv_usec = 0;

	event_init();

	/* For each tap device specified, initialise an event for it */
	TAILQ_FOREACH(tap_device, &taps, entry) {
		/* Update the tap_device struct with the server fd */
		tap_device->server_fd = server_fd;
		/* Update the tap device with the timeout event and value */
		tap_device->timeout_ev = &timeout_ev;
		tap_device->idle_timeout = idle_timeout;

		event_set(&tap_device->ev, EVENT_FD(&tap_device->ev), 
		    EV_READ | EV_PERSIST, tap_device_cb, tap_device);
		event_add(&tap_device->ev, NULL);
	}


	server_args = malloc(sizeof(struct server_args));
	server_args->tap_list = &taps;
	server_args->timeout_ev = &timeout_ev;
	server_args->idle_timeout = idle_timeout;

	server_event = malloc(sizeof(struct server_ev));

	/* Initialise the server callback event */
	event_set(&server_event->ev, server_fd, EV_READ | EV_PERSIST, 
	    server_response_cb, server_args);
	event_add(&server_event->ev, NULL);

	/* Initialise the timeout event - If a timeout is specified properly */
	if (idle_timeout != 0) {
		evtimer_set(&timeout_ev, timeout_cb, NULL);
		evtimer_add(&timeout_ev, &timeout_value);
	}
	event_dispatch();

	return (0);
}