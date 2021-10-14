#ifndef CSOCK_H
#define CSOCK_H

#define CSOCK_RESULT_SUCCESS 0
#define CSOCK_RESULT_NONE_PENDING 1
#define CSOCK_RESULT_INIT_FAILED -1
#define CSOCK_RESULT_INVALID_HOST -2
#define CSOCK_RESULT_BIND_FAILED -3
#define CSOCK_RESULT_SOCKET_CREATE_FAILED -4
#define CSOCK_RESULT_FAILED_GENERIC -5
#define CSOCK_RESULT_CONNECT_FAILED -6

struct csock_addr_t
{
	unsigned int host;
	unsigned short port;
};

struct csock_t
{
	int handle;
};

int csock_init();
int csock_translate(csock_addr_t* address, const char* host, unsigned short port);
int csock_shutdown();
int csock_close(csock_t* socket);
int csock_listen(csock_t* sock, unsigned int port);
int csock_connect(csock_t* sock, csock_addr_t addr);
int csock_accept(csock_t* listening_socket, csock_t* remote_socket, csock_addr_t* remote_addr);
int csock_send(csock_t* remote_socket, const void* data, int size);
int csock_receive(csock_t* sock, unsigned char* data, int maxlen);
int csock_peek(csock_t* sock, unsigned char* data, int maxlen);
#endif

#ifdef CSOCK_IMPLEMENTATION

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <stdint.h>
#pragma comment(lib, "wsock32.lib")
#undef AddJob
#else
#include <cstring>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#endif

int csock_init()
{
#ifdef _WIN32
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
	{
		return CSOCK_RESULT_INIT_FAILED;
	}
#endif
	return CSOCK_RESULT_SUCCESS;
}

int csock_translate(csock_addr_t* address, const char* host, unsigned short port)
{
	if (host == NULL) {
		address->host = INADDR_ANY;
	}
	else
	{
		address->host = inet_addr(host);
		if (address->host == INADDR_NONE)
		{
			auto hostent = gethostbyname(host);
			if (hostent)
			{
				memcpy(&address->host, hostent->h_addr, hostent->h_length);
			}
			else
			{
				return CSOCK_RESULT_INVALID_HOST;
			}
		}
	}
	address->port = port;
	return CSOCK_RESULT_SUCCESS;
}


int csock_shutdown()
{
#ifdef _WIN32
	WSACleanup();
#endif
	return CSOCK_RESULT_SUCCESS;
}

int csock_close(csock_t* socket)
{
	if (socket->handle)
	{
#ifdef _WIN32
		closesocket(socket->handle);
#else
		close(socket->handle);
#endif
	}
	return CSOCK_RESULT_SUCCESS;
}

int csock_listen(csock_t* sock, unsigned int port)
{
	sock->handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock->handle <= 0) {
		csock_close(sock);
		return CSOCK_RESULT_SOCKET_CREATE_FAILED;
	}

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);

	if (bind(sock->handle, (const struct sockaddr*)&address, sizeof(struct sockaddr_in)) != 0)
	{
		csock_close(sock);
		return CSOCK_RESULT_BIND_FAILED;
	}

#ifndef SOMAXCONN
#define SOMAXCONN 10
#endif
	if (listen(sock->handle, SOMAXCONN) != 0)
	{
		csock_close(sock);
		return CSOCK_RESULT_SOCKET_CREATE_FAILED;
	}

	return CSOCK_RESULT_SUCCESS;
}

int csock_connect(csock_t* sock, csock_addr_t addr)
{
	sock->handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock->handle <= 0)
	{
		csock_close(sock);
		return CSOCK_RESULT_SOCKET_CREATE_FAILED;
	}

	sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(0);

	if (bind(sock->handle, (const struct sockaddr*)&address, sizeof(address)) != 0)
	{
		csock_close(sock);
		return CSOCK_RESULT_BIND_FAILED;
	}

	address.sin_port = htons(addr.port);
	address.sin_addr.s_addr = addr.host;

	if (connect(sock->handle, (const struct sockaddr*)&address, sizeof(address)) == -1)
	{
		csock_close(sock);
		return CSOCK_RESULT_CONNECT_FAILED;
	}

	return 0;
}

int csock_accept(csock_t* listening_socket, csock_t* remote_socket, csock_addr_t* remote_addr)
{
	fd_set readfd;
	FD_ZERO(&readfd);
	FD_SET(listening_socket->handle, &readfd);

	timeval timer;
	timer.tv_sec = 0;
	timer.tv_usec = 0;
	int retval = select(listening_socket->handle + 1, &readfd, NULL, NULL, &timer);
	if (retval == 0)
		return CSOCK_RESULT_NONE_PENDING;
	else if (retval == -1) {
		csock_close(listening_socket);
		return CSOCK_RESULT_FAILED_GENERIC;
	}

#ifdef _WIN32
	typedef int socklen_t;
#endif
	sockaddr_in address;
	socklen_t addrlen = sizeof(address);
	int handle = accept(listening_socket->handle, (struct sockaddr*)&address, &addrlen);

	if (handle == -1)
		return CSOCK_RESULT_FAILED_GENERIC;

	remote_addr->host = address.sin_addr.s_addr;
	remote_addr->port = ntohs(address.sin_port);

	remote_socket->handle = handle;

	return CSOCK_RESULT_SUCCESS;
}

int csock_send(csock_t* remote_socket, const void* data, int size)
{
	int sent_bytes = send(remote_socket->handle, (const char*)data, size, 0);
	if (sent_bytes != size)
	{
		return CSOCK_RESULT_FAILED_GENERIC;
	}

	return CSOCK_RESULT_SUCCESS;
}


// returns amount of bytes read
int csock_receive(csock_t* sock, unsigned char* data, int maxlen)
{

	if (maxlen == 0)
		return 0;
	int received_bytes = recv(sock->handle, (char*)data, maxlen, MSG_WAITALL);
	if (received_bytes < 0)
	{
		return CSOCK_RESULT_FAILED_GENERIC;
	}
	return received_bytes;
}

// returns amount of bytes 'peeked'
int csock_peek(csock_t* sock, unsigned char* data, int maxlen)
{
	if (data == 0)
	{
		unsigned long available;
#ifdef _WIN32
		ioctlsocket(sock->handle, FIONREAD, &available);
#else
		ioctl(sock->handle, FIONREAD, &available);
#endif
		return available;
	}
	else
	{
		if (maxlen == 0)
			return 0;
		int received_bytes = recv(sock->handle, (char*)data, maxlen, MSG_PEEK);
		if (received_bytes < 0)
		{
			return CSOCK_RESULT_FAILED_GENERIC;
		}
		return received_bytes;
	}
}
#endif
