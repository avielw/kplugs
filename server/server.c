#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <malloc.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_IP	"127.0.0.1"
#define LISTEN_PORT	6565
#define KPLUGS_DEV	"/dev/kplugs"

#define KPLUGS_IOCTYPE (154)
#define COMMAND_SIZE   (9 * sizeof(long))

int to_exit = 0;


typedef enum {
	ALLOC,
	FREE,
	WRITEMEM,
	READMEM,
	WRITE,
	READ,
	IOCTL,
} packettype_t;


typedef struct {
	unsigned long size;
	unsigned long type;
} packet_t;

typedef struct {
	unsigned long size;
} packet_alloc_t;

typedef struct {
	void *addr;
} packet_free_t;

typedef struct {
	void *addr;
} packet_writemem_t;

typedef struct {
	unsigned long size;
	void *addr;
} packet_readmem_t;

typedef struct {
	unsigned long size;
} packet_read_t;

typedef struct {
    unsigned long cmd;
    char ioctl_buf[COMMAND_SIZE];
} packet_ioctl_t;


int sendall(int sock, void *buf, unsigned long size)
{
	int temp;
	unsigned long all = 0;

	while (all < (long)size) {
		temp = send(sock, buf + all, size - all, 0);
		if (temp <= 0) {
			return 1;
		}
		all += temp;
	}
	return 0;
}

int recvall(int sock, void *buf, unsigned long size)
{
	int temp;
	unsigned long all = 0;

	while (all < (long)size) {
		temp = recv(sock, buf + all, size - all, 0);
		if (temp <= 0) {
			return 1;
		}
		all += temp;
	}
	return 0;
}

void *handle_connection(void *param)
{
	int sock = (int)(unsigned long)param;
	int word_size = sizeof(unsigned long);
	char little_endian;
	int fd;

	packet_t packet;
	packet_alloc_t palloc;
	packet_free_t pfree;
	packet_writemem_t pwritemem;
	packet_readmem_t preadmem;
	packet_read_t pread;
	packet_ioctl_t pioctl;

	void *data = NULL;
	unsigned long data_len = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	little_endian = 1;
#else
	little_endian = 0;
#endif

#define REALLOC_DATA(new_len) do { \
	if (new_len > data_len) { \
		if (data) {free(data);} \
		data = malloc(new_len); \
		if (!data) {goto end;} \
		data_len = new_len; \
	} \
} while(0)

#define DO_REPLY(buf, send_size) do { \
	packet.size = send_size; \
	if (sendall(sock, &packet, sizeof(packet))) { \
		goto end; \
	} \
	if (send_size && sendall(sock, buf, send_size)) { \
		goto end; \
	} \
} while (0)

	fd = open(KPLUGS_DEV, O_RDWR);
	if (fd < 0) {
		goto end;
	}

	if (sendall(sock, &little_endian, sizeof(little_endian))) {
		goto end;
	}

	if (sendall(sock, &word_size, sizeof(word_size))) {
		goto end;
	}

	while (1) {
		if (recvall(sock, &packet, sizeof(packet))) {
			goto end;
		}

		switch (packet.type) {
		case ALLOC:
			if (packet.size != sizeof(palloc)) {
				goto end;
			}
			if (recvall(sock, &palloc, sizeof(palloc))) {
				goto end;
			}
			REALLOC_DATA(sizeof(void *));
			*(void **)data = malloc(palloc.size);
			if (*(void **)data) {
				memset(*(void **)data, 0, palloc.size);
			}
			DO_REPLY(data, sizeof(void *));
			break;

		case FREE:
			if (packet.size != sizeof(pfree)) {
				goto end;
			}
			if (recvall(sock, &pfree, sizeof(pfree))) {
				goto end;
			}
			free(pfree.addr);
			DO_REPLY(data, 0);
			break;

		case WRITEMEM:
			if (packet.size < sizeof(pwritemem)) {
				goto end;
			}
			if (recvall(sock, &pwritemem, sizeof(pwritemem))) {
				goto end;
			}
			if (recvall(sock, pwritemem.addr, packet.size - sizeof(pwritemem))) {
				goto end;
			}
			DO_REPLY(data, 0);
			break;

		case READMEM:
			if (packet.size != sizeof(preadmem)) {
				goto end;
			}
			if (recvall(sock, &preadmem, sizeof(preadmem))) {
				goto end;
			}
			DO_REPLY(preadmem.addr, preadmem.size);
			break;

		case WRITE:
			REALLOC_DATA(packet.size);
			if (recvall(sock, data, packet.size)) {
				goto end;
			}
			REALLOC_DATA(sizeof(unsigned long));
			*(unsigned long *)data = (unsigned long)write(fd, data, packet.size);
			DO_REPLY(data, sizeof(unsigned long));
			break;

		case READ:
			if (packet.size != sizeof(pread)) {
				goto end;
			}
			if (recvall(sock, &pread, sizeof(pread))) {
				goto end;
			}
			REALLOC_DATA(pread.size + sizeof(unsigned long));
			memset(data, 0, pread.size + sizeof(unsigned long));
			*(unsigned long *)data = (unsigned long)read(fd, data + sizeof(unsigned long), pread.size);
			DO_REPLY(data, pread.size + sizeof(unsigned long));
			break;

		case IOCTL:
			if (packet.size != sizeof(pioctl)) {
				goto end;
			}
			if (recvall(sock, &pioctl, sizeof(pioctl))) {
				goto end;
			}

			pioctl.cmd = (unsigned long)ioctl(fd, _IOWR(KPLUGS_IOCTYPE, (int)pioctl.cmd, pioctl.ioctl_buf), pioctl.ioctl_buf);
			DO_REPLY(&pioctl, sizeof(pioctl));
			break;

		default:
			goto end;
		}
	}

end:
	if (data) {
		free(data);
	}
	if (fd >= 0) {
		close(fd);
	}
	close(sock);

	return NULL;
}

void sig_handler(int sig)
{
	to_exit = 1;
}

int main(int argc, char ** argv)
{
	struct sockaddr_in server_addr;
	int sock, new_sock;
	pthread_t thread;
	int ret;
	fd_set set;

	if (argc != 1) {
		if (argc) {
			printf("Usage: %s\n", argv[0]);
		}
		return 1;
	}

	sock = socket(AF_INET , SOCK_STREAM , 0);
	if (sock < 0) {
		printf("Error: creating a socket\n");
		return 1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(LISTEN_PORT);

	if (bind(sock, (struct sockaddr *)&server_addr , sizeof(server_addr)) < 0) {
		printf("Error: bind\n");
		return 1;
	}

	if (listen(sock, 5) < 0) {
		printf("Error: listen\n");
		return 1;
	}

	signal(SIGINT, sig_handler);

	while (1) {
		FD_ZERO(&set);
		FD_SET(sock, &set);
		ret = select(sock + 1, &set, NULL, NULL, NULL);
		if (ret > 0) {
			new_sock = accept(sock, NULL, NULL);
			if (new_sock >= 0) {
				if (pthread_create(&thread, NULL, handle_connection, (void *)(unsigned long)new_sock) < 0) {
					printf("Error: pthread_create");
					return 0;
				}
				pthread_detach(thread);
			}
		}
		if (to_exit) {
			printf("Stopping the server.\n");
			break;
		}
	}

	close(sock);

	return 0;
}
