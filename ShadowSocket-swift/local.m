#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <secure/_string.h>
#include <sys/fcntl.h>
#import <Foundation/Foundation.h>

#include "local.h"
#include "socks5.h"

#define ADDR_STR_LEN 512

#define SAVED_STR_LEN 512

char _server[SAVED_STR_LEN];
char _remote_port[SAVED_STR_LEN];
char _method[SAVED_STR_LEN];
char _password[SAVED_STR_LEN];

int setnonblocking(int fd) {
    int flags;
    if (-1 ==(flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);// 设置fd的 旗标为0 改变方式为O_NONBLOCK
}

int create_and_bind(const char *port) {
    struct addrinfo hints;// 申明接口转换结构体
    struct addrinfo *result, *rp;// 申明接口转换的结构体指针
    int s, listen_sock = 0;

    memset(&hints, 0, sizeof(struct addrinfo));//初始化指针hints
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo("127.0.0.1", port, &hints, &result);// 做接口转换   getaddrinfo函数能够处理名字到地址以及服务到端口这两 种转换，返回的是一个sockaddr结构的链表而不是一个地址清单
    if (s != 0) {
        NSLog(@"getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);//构建监听socket
        int opt = 1;
        //设置socket的不同模式
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));//设置socket 接口listen_socket 类型：SOL_SOCKET 名称 SO_REUSEADDR ，socket接口：1 长度1
        setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));//设置tcp的socket
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
        if (listen_sock == -1)
            continue;

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);//bind()用来设置给参数sockfd 的socket 一个名称. 此名称由参数my_addr 指向一sockaddr 结构,对于不同的socket domain 定义了一个通用的数据结构
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            perror("bind");
        }

        close(listen_sock);
    }

    if (rp == NULL) {
        NSLog(@"Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static void server_recv_cb (EV_P_ ev_io *w, int revents) {
	struct server_ctx *server_recv_ctx = (struct server_ctx *)w;
	struct server *server = server_recv_ctx->server;
	struct remote *remote = server->remote;
//    NSLog(@"server_recv_cb %d", server?server->stage:-1);

    if (remote == NULL) {
        close_and_free_server(EV_A_ server);
        return;
    }

    char *buf = remote->buf;
    size_t *buf_len = &remote->buf_len;
    if (server->stage != 5) {
        buf = server->buf;
        buf_len = &server->buf_len;
    }

    ssize_t r = recv(server->fd, buf, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        *buf_len = 0;
        close_and_free_server(EV_A_ server);
        if (remote != NULL) {
            ev_io_start(EV_A_ &remote->send_ctx->io);
        }
        return;
    } else if(r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            perror("server recv");
            close_and_free_server(EV_A_ server);
            close_and_free_remote(EV_A_ remote);
            return;
        }
    }

    // local socks5 server
    if (server->stage == 5) {
        encrypt_buf(&(remote->send_encryption_ctx), (unsigned char *)remote->buf, (size_t *)&r);
        ssize_t w = send(remote->fd, remote->buf, (size_t)r, 0);
        if(w == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                remote->buf_len = (size_t)r;
                // no data, wait for send
                ev_io_stop(EV_A_ &server_recv_ctx->io);
                ev_io_start(EV_A_ &remote->send_ctx->io);
                return;
            } else {
                perror("send");
                close_and_free_server(EV_A_ server);
                close_and_free_remote(EV_A_ remote);
                return;
            }
        } else if(w < r) {
            char *pt = remote->buf;
            char *et = pt + r;
            while (pt + w < et) {
                *pt = *(pt + w);
                pt++;
            }
            remote->buf_len = (size_t)r - w;
            ev_io_stop(EV_A_ &server_recv_ctx->io);
            ev_io_start(EV_A_ &remote->send_ctx->io);
            return;
        }
    } else if (server->stage == 0) {// 将socket0 改成 socket1
        struct method_select_response response;
        response.ver = SOCKS_VERSION;
        response.method = 0;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, sizeof(response), 0);
        server->stage = 1;
        return;
    } else if (server->stage == 1) {// 将socket1 改成 socket5
        struct socks5_request *request = (struct socks5_request *)server->buf;

        if (request->cmd != SOCKS_CMD_CONNECT) {
            NSLog(@"unsupported cmd: %d\n", request->cmd);
            struct socks5_response response;
            response.ver = SOCKS_VERSION;
            response.rep = SOCKS_CMD_NOT_SUPPORTED;
            response.rsv = 0;
            response.atyp = SOCKS_IPV4;
            char *send_buf = (char *)&response;
            send(server->fd, send_buf, 4, 0);
            close_and_free_server(EV_A_ server);
            close_and_free_remote(EV_A_ remote);
            return;
        }

        char addr_to_send[ADDR_STR_LEN];
        size_t addr_len = 0;
        addr_to_send[addr_len++] = request->atyp;


        char addr_str[ADDR_STR_LEN];
        // get remote addr and port
        if (request->atyp == SOCKS_IPV4) {

            // IP V4
            size_t in_addr_len = sizeof(struct in_addr);
            memcpy(addr_to_send + addr_len, server->buf + 4, in_addr_len + 2);
            addr_len += in_addr_len + 2;
//                addr_to_send[addr_len] = 0;

            // now get it back and print it
            inet_ntop(AF_INET, server->buf + 4, addr_str, ADDR_STR_LEN);

//#if !TARGET_OS_IPHONE
            NSLog(@"Connecting an IPv4 address, please configure your browser to use hostname instead: https://github.com/clowwindy/shadowsocks/wiki/Troubleshooting");
//#endif
        } else if (request->atyp == SOCKS_DOMAIN) {
            // Domain name
            unsigned char name_len = *(unsigned char *)(server->buf + 4);
            addr_to_send[addr_len++] = name_len;
            memcpy(addr_to_send + addr_len, server->buf + 4 + 1, name_len);
            memcpy(addr_str, server->buf + 4 + 1, name_len);
            addr_str[name_len] = '\0';
            addr_len += name_len;

            // get port
            addr_to_send[addr_len++] = *(unsigned char *)(server->buf + 4 + 1 + name_len);
            addr_to_send[addr_len++] = *(unsigned char *)(server->buf + 4 + 1 + name_len + 1);
//                addr_to_send[addr_len] = 0;

//#if !TARGET_OS_IPHONE
            char temp[256];
            memcpy(temp, server->buf + 4 + 1, name_len);
            temp[name_len] = '\0';
            NSLog(@"Connecting %@", [NSString stringWithCString:addr_str encoding:NSUTF8StringEncoding]);
//#endif
        } else {
            NSLog(@"unsupported addrtype: %d\n", request->atyp);
            close_and_free_server(EV_A_ server);
            close_and_free_remote(EV_A_ remote);
            return;
        }

        int n = send_encrypt(&(remote->send_encryption_ctx), remote->fd, (unsigned char *)addr_to_send, &addr_len, 0);
        if (n != addr_len) {
            NSLog(@"header not completely sent: n != addr_len: n==%d, addr_len==%d", n, (int)addr_len);
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        // Fake reply
        struct socks5_response response;
        response.ver = SOCKS_VERSION;
        response.rep = 0;
        response.rsv = 0;
        response.atyp = SOCKS_IPV4;

        struct in_addr sin_addr;
        inet_aton("0.0.0.0", &sin_addr);

        memcpy(server->buf, &response, 4);
        memcpy(server->buf + 4, &sin_addr, sizeof(struct in_addr));
        *((unsigned short *)(server->buf + 4 + sizeof(struct in_addr)))
            = (unsigned short) htons(atoi(_remote_port));

        size_t reply_size = 4 + sizeof(struct in_addr) + sizeof(unsigned short);
        ssize_t r = send(server->fd, server->buf, reply_size, 0);
        if (r < reply_size) {
            NSLog(@"header not complete sent\n");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        ev_io_start(EV_A_ &remote->recv_ctx->io);

        server->stage = 5;
	}
}

static void server_send_cb (EV_P_ ev_io *w, int revents) {
	struct server_ctx *server_send_ctx = (struct server_ctx *)w;
	struct server *server = server_send_ctx->server;
	struct remote *remote = server->remote;
	if (server->buf_len == 0) {
		// close and free
		close_and_free_server(EV_A_ server);
		close_and_free_remote(EV_A_ remote);
		return;
	} else {
		// has data to send
		ssize_t r = send(server->fd, server->buf,
				server->buf_len, 0);
		if (r < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("send");
				close_and_free_server(EV_A_ server);
				close_and_free_remote(EV_A_ remote);
				return;
			}
			return;
		}
		if (r < server->buf_len) {
			// partly sent, move memory, wait for the next time to send
			char *pt = server->buf;
            char *et = pt + server->buf_len;
            while (pt + r < et) {
				*pt = *(pt + r);
                pt++;
			}
			server->buf_len -= r;
			return;
		} else {
			// all sent out, wait for reading
            server->buf_len = 0;
			ev_io_stop(EV_A_ &server_send_ctx->io);
			if (remote != NULL) {
				ev_io_start(EV_A_ &remote->recv_ctx->io);
			} else {
				close_and_free_server(EV_A_ server);
				close_and_free_remote(EV_A_ remote);
				return;
			}
		}
	}

}

static void remote_recv_cb (EV_P_ ev_io *w, int revents) {
	struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
	struct remote *remote = remote_recv_ctx->remote;
	struct server *server = remote->server;
	if (server == NULL) {
		close_and_free_remote(EV_A_ remote);
		return;
	}
    ssize_t r = recv(remote->fd, server->buf, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        server->buf_len = 0;
        close_and_free_remote(EV_A_ remote);
        if (server != NULL) {
            ev_io_start(EV_A_ &server->send_ctx->io);
        }
        return;
    } else if(r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            perror("remote recv");
            close_and_free_server(EV_A_ server);
            close_and_free_remote(EV_A_ remote);
            return;
        }
    }
    decrypt_buf(&(remote->recv_encryption_ctx), (unsigned char *)server->buf, (size_t*)&r);
    ssize_t s = send(server->fd, server->buf, (size_t)r, 0);
    if(s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            server->buf_len = (size_t)r;
            // no data, wait for send
            ev_io_stop(EV_A_ &remote_recv_ctx->io);
            ev_io_start(EV_A_ &server->send_ctx->io);
            return;
        } else {
            perror("send");
            close_and_free_server(EV_A_ server);
            close_and_free_remote(EV_A_ remote);
            return;
        }
    } else if(s < r) {
        char *pt = server->buf;
        char *et = pt + r;
        while (pt + s < et) {
            *pt = *(pt + s);
            pt++;
        }
        server->buf_len = (size_t)r - s;
        ev_io_stop(EV_A_ &remote_recv_ctx->io);
        ev_io_start(EV_A_ &server->send_ctx->io);
        return;
    }
}
//
static void remote_send_cb (EV_P_ ev_io *w, int revents) {
	struct remote_ctx *remote_send_ctx = (struct remote_ctx *)w;
	struct remote *remote = remote_send_ctx->remote;
	struct server *server = remote->server;

	if (!remote_send_ctx->connected) {

		socklen_t len;
		struct sockaddr_storage addr;
		len = sizeof addr;
		int r = getpeername(remote->fd, (struct sockaddr*)&addr, &len);//这个函数可以取得一个已经连接上的套接字的远程信息（比如IP 地址和端口） 获取链接socket地址
		if (r == 0) {
			remote_send_ctx->connected = 1;
			ev_io_stop(EV_A_ &remote_send_ctx->io);
			ev_io_start(EV_A_ &server->recv_ctx->io);
		} else {
			perror("getpeername");
			// not connected
			close_and_free_remote(EV_A_ remote);
			close_and_free_server(EV_A_ server);
			return;
		}
	} else {
		if (remote->buf_len == 0) {
			// close and free
			close_and_free_remote(EV_A_ remote);
			close_and_free_server(EV_A_ server);
			return;
		} else {
			// has data to send
			ssize_t r = send(remote->fd, remote->buf,
					remote->buf_len, 0);// 发送要移除的socket的套接字符，缓存信息，信息的长度
            // 以下判断缩减本地内存
			if (r < 0) {
				if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("send");
					// close and free
					close_and_free_remote(EV_A_ remote);
					close_and_free_server(EV_A_ server);
					return;
				}
				return;
			}
			if (r < remote->buf_len) {
				// partly sent, move memory, wait for the next time to send
                char *pt = remote->buf;
                char *et = pt + remote->buf_len;
                while (pt + r < et) {
                    *pt = *(pt + r);
                    pt++;
                }
				remote->buf_len -= r;
				return;
			} else {
				// all sent out, wait for reading
				ev_io_stop(EV_A_ &remote_send_ctx->io);
				if (server != NULL) {
					ev_io_start(EV_A_ &server->recv_ctx->io);
				} else {
					close_and_free_remote(EV_A_ remote);
					close_and_free_server(EV_A_ server);
					return;
				}
			}
		}

	}
}
//定义一个remote的结构体指针 放置遥控的socket值
struct remote* new_remote(int fd) {
	struct remote *remote;
	remote = malloc(sizeof(struct remote));
	remote->fd = fd;
    remote->buf_len = 0;
	remote->recv_ctx = malloc(sizeof(struct remote_ctx));
	remote->send_ctx = malloc(sizeof(struct remote_ctx));
	ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
	ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
	remote->recv_ctx->remote = remote;
	remote->recv_ctx->connected = 0;
	remote->send_ctx->remote = remote;
	remote->send_ctx->connected = 0;
    remote->server = NULL;
    init_encryption(&(remote->recv_encryption_ctx));
    init_encryption(&(remote->send_encryption_ctx));
	return remote;
}

//释放
void free_remote(struct remote *remote) {
	if (remote != NULL) {
		if (remote->server != NULL) {
			remote->server->remote = NULL;
		}
		free(remote->recv_ctx);
		free(remote->send_ctx);
        cleanup_encryption(&(remote->recv_encryption_ctx));
        cleanup_encryption(&(remote->send_encryption_ctx));
		free(remote);
	}
}
// 关闭和释放包
void close_and_free_remote(EV_P_ struct remote *remote) {
	if (remote != NULL) {
		ev_io_stop(EV_A_ &remote->send_ctx->io);
		ev_io_stop(EV_A_ &remote->recv_ctx->io);
		close(remote->fd);
		free_remote(remote);
	}
}
// 定义sever socket的值
struct server* new_server(int fd) {
	struct server *server;
	server = malloc(sizeof(struct server));
	server->fd = fd;
    server->buf_len = 0;
	server->recv_ctx = malloc(sizeof(struct server_ctx));
	server->send_ctx = malloc(sizeof(struct server_ctx));
	ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
	ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
	server->recv_ctx->server = server;
	server->recv_ctx->connected = 0;
	server->send_ctx->server = server;
	server->send_ctx->connected = 0;
    server->stage = 0;
    server->remote = NULL;
	return server;
}

// 释放
void free_server(struct server *server) {
	if (server != NULL) {
		if (server->remote != NULL) {
			server->remote->server = NULL;
		}
		free(server->recv_ctx);
		free(server->send_ctx);
		free(server);
	}
}
// 关闭和释放
void close_and_free_server(EV_P_ struct server *server) {
	if (server != NULL) {
		ev_io_stop(EV_A_ &server->send_ctx->io);//停止已激活的server send_ctx的IO 发送数据的IO
		ev_io_stop(EV_A_ &server->recv_ctx->io);//停止已激活的server recv_ctx的IO 接收数据的IO
		close(server->fd);// 关闭服务器端文件描述符文件，套接字将不会在允许进行读操作和写操作
		free_server(server);//释放
	}
}
// 接收返回包，设置socket
static void accept_cb (EV_P_ ev_io *w, int revents)
{
	struct listen_ctx *listener = (struct listen_ctx *)w;
	int serverfd;
	while (1) {
		serverfd = accept(listener->fd, NULL, NULL);
		if (serverfd == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("accept");
            }
			break;
		}
		setnonblocking(serverfd);
        int opt = 1;
        setsockopt(serverfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
		struct server *server = new_server(serverfd);
		struct addrinfo hints, *res;
		int sockfd;
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		int r = getaddrinfo(_server, _remote_port, &hints, &res);//函数能够处理名字到地址以及服务到端口这两 种转换，返回的是一个sockaddr结构的链表而不是一个地址清单
        if (r) {
            fprintf(stderr, "getaddrinfo: %s", gai_strerror(r));
			free_server(server);
			continue;
        }
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));//采用tcp协议
        setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));//把操作套接字的层定义在 SOL_SOCKET 上
		if (sockfd < 0) {
			perror("socket");
			close(sockfd);
			free_server(server);
			continue;
		}
		setnonblocking(sockfd);// 重新设置sockfd的旗标
		struct remote *remote = new_remote(sockfd);
		server->remote = remote;
		remote->server = server;
		connect(sockfd, res->ai_addr, res->ai_addrlen);// 连接远程
		freeaddrinfo(res);
		// listen to remote connected event
		ev_io_start(EV_A_ &remote->send_ctx->io);
		break;
	}
}

void set_config(const char *server, const char *remote_port, const char* password, const char* method) {
    assert(strlen(server) < SAVED_STR_LEN);
    assert(strlen(remote_port) < SAVED_STR_LEN);
    assert(strlen(password) < SAVED_STR_LEN);
    assert(strlen(method) < SAVED_STR_LEN);
    strcpy(_server, server);
    strcpy(_remote_port, remote_port);
    strcpy(_password, password);
    strcpy(_method, method);
#ifdef DEBUG
    NSLog(@"calculating ciphers");
#endif
    // TODO move to encrypt.m
    config_encryption(password, method);
}
// 监听8864端口，将坚定的socket进行设置
int local_main ()
{
    int listenfd;
    // binss: 更换绑定端口
    const char * port = "8864";
    listenfd = create_and_bind(port);
    if (listenfd < 0) {
#ifdef DEBUG
        NSLog(@"bind() error..");
#endif
        return 1;
    }
    if (listen(listenfd, SOMAXCONN) == -1) {
        NSLog(@"listen() error.");
        return 1;
    }
#ifdef DEBUG
    NSLog(@"server listening at port %s\n", port);
#endif

    setnonblocking(listenfd);
    struct listen_ctx listen_ctx;
    listen_ctx.fd = listenfd;
    struct ev_loop *loop = EV_DEFAULT;
    ev_io_init (&listen_ctx.io, accept_cb, listenfd, EV_READ);
    ev_io_start (loop, &listen_ctx.io);
    ev_run (loop, 0);
    return 0;
}

