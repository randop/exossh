/*
 * Copyright 2026 Randolph Ledesma
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define VERSION_MAJOR 1
#define VERSION_MINOR 3
#define VERSION_PATCH 0

#define STRINGIFY0(x) #x
#define STRINGIFY(x) STRINGIFY0(x)

#define VERSION_STRING                                                         \
  STRINGIFY(VERSION_MAJOR)                                                     \
  "." STRINGIFY(VERSION_MINOR) "." STRINGIFY(VERSION_PATCH)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <uv.h>

#define PORT 2222
#define INTERVAL_LINE_BANNER_MS 10000
#define MAX_LINE_LENGTH 32
#define READ_BUFFER_SIZE 1024
#define MAX_BACKLOG 64

static const uint8_t PROXY_V2_SIG[12] = {0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d,
                                         0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a};

static unsigned rand16(unsigned long s[1]) {
  s[0] = s[0] * 1103515245UL + 12345UL;
  return (s[0] >> 16) & 0xffff;
}

static int randline(char *line, int maxlen, unsigned long s[1]) {
  int len = 3 + rand16(s) % (maxlen - 2);
  for (int i = 0; i < len - 2; i++) {
    line[i] = 32 + rand16(s) % 95;
  }
  line[len - 2] = 13;
  line[len - 1] = 10;
  if (memcmp(line, "SSH-", 4) == 0) {
    line[0] = 'X';
  }
  return len;
}

typedef struct {
  uv_tcp_t handle;
  uv_timer_t timer;
  int refcount;
  uv_write_t write_req;
  char read_buf[READ_BUFFER_SIZE];
  unsigned long rng_state;
  char ip_address[INET6_ADDRSTRLEN];
  int proxy_done;
} client_t;

static int parse_proxy_v1(const char *data, size_t len, char *out_ip,
                          size_t out_ip_len) {
  if (len < 8 || memcmp(data, "PROXY ", 6) != 0) {
    return 0;
  }

  const char *end = memchr(data, '\n', len);
  if (!end) {
    return 0;
  }

  size_t hdr_len = (size_t)(end - data) + 1;
  if (hdr_len > 108) {
    return -1;
  }

  char hdr[128];
  if (hdr_len >= sizeof(hdr)) {
    return -1;
  }
  memcpy(hdr, data, hdr_len);
  hdr[hdr_len - 1] = '\0';

  char proto[8], src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
  int src_port, dst_port;

  if (sscanf(hdr, "PROXY %7s %45s %45s %d %d", proto, src, dst, &src_port,
             &dst_port) != 5) {
    if (strncmp(hdr, "PROXY UNKNOWN", 13) == 0) {
      strncpy(out_ip, "unknown", out_ip_len - 1);
      out_ip[out_ip_len - 1] = '\0';
      return (int)hdr_len;
    }
    return -1;
  }

  if (strcmp(proto, "TCP4") != 0 && strcmp(proto, "TCP6") != 0) {
    return -1;
  }

  strncpy(out_ip, src, out_ip_len - 1);
  out_ip[out_ip_len - 1] = '\0';
  return (int)hdr_len;
}

static int parse_proxy_v2(const uint8_t *data, size_t len, char *out_ip,
                          size_t out_ip_len) {
  if (len < 16) {
    return 0;
  }
  if (memcmp(data, PROXY_V2_SIG, 12) != 0) {
    return 0;
  }

  uint8_t ver_cmd = data[12];
  uint8_t fam_proto = data[13];
  uint16_t addr_len = (uint16_t)((data[14] << 8) | data[15]);

  size_t total = 16 + addr_len;
  if (len < total) {
    return 0;
  }

  if ((ver_cmd & 0xf0) != 0x20) {
    return -1;
  }
  uint8_t cmd = ver_cmd & 0x0f;
  if (cmd != 0x00 && cmd != 0x01) {
    return -1;
  }

  if (cmd == 0x00) {
    strncpy(out_ip, "unknown", out_ip_len - 1);
    out_ip[out_ip_len - 1] = '\0';
    return (int)total;
  }

  uint8_t family = (fam_proto >> 4) & 0x0f;

  if (family == 0x01) {
    if (addr_len < 12) {
      return -1;
    }
    struct in_addr src;
    memcpy(&src, data + 16, 4);
    if (inet_ntop(AF_INET, &src, out_ip, (socklen_t)out_ip_len) == NULL) {
      return -1;
    }
  } else if (family == 0x02) {
    if (addr_len < 36) {
      return -1;
    }
    struct in6_addr src;
    memcpy(&src, data + 16, 16);
    if (inet_ntop(AF_INET6, &src, out_ip, (socklen_t)out_ip_len) == NULL) {
      return -1;
    }
  } else if (family == 0x00) {
    strncpy(out_ip, "unknown", out_ip_len - 1);
    out_ip[out_ip_len - 1] = '\0';
  } else {
    return -1;
  }

  return (int)total;
}

static int try_parse_proxy(const char *data, size_t len, char *out_ip,
                           size_t out_ip_len) {
  int n = parse_proxy_v2((const uint8_t *)data, len, out_ip, out_ip_len);
  if (n != 0) {
    return n;
  }
  return parse_proxy_v1(data, len, out_ip, out_ip_len);
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size,
                         uv_buf_t *buf) {
  client_t *client = (client_t *)handle->data;
  buf->base = client->read_buf;
  buf->len = sizeof(client->read_buf);
  (void)suggested_size;
}

static void on_close(uv_handle_t *handle) {
  client_t *client = (client_t *)handle->data;
  if (--client->refcount == 0) {
    printf("%s disconnected\n", client->ip_address);
    free(client);
  }
}

static void on_read(uv_stream_t *client_stream, ssize_t nread,
                    const uv_buf_t *buf) {
  uv_handle_t *handle = (uv_handle_t *)client_stream;
  client_t *client = (client_t *)handle->data;

  if (nread < 0) {
    if (nread != UV_EOF) {
      fprintf(stderr, "Client read error: %s\n", uv_err_name((int)nread));
    }
    uv_close((uv_handle_t *)&client->handle, on_close);
    uv_close((uv_handle_t *)&client->timer, on_close);
    return;
  }

  if (nread == 0) {
    return;
  }

  if (!client->proxy_done) {
    int consumed = try_parse_proxy(buf->base, (size_t)nread, client->ip_address,
                                   sizeof(client->ip_address));
    if (consumed > 0) {
      printf("%s connected\n", client->ip_address);
      client->proxy_done = 1;
      return;
    }
    if (consumed < 0) {
      fprintf(stderr, "Malformed PROXY header from %s\n", client->ip_address);
      uv_close((uv_handle_t *)&client->handle, on_close);
      uv_close((uv_handle_t *)&client->timer, on_close);
      return;
    }
    client->proxy_done = 1;
  }

  (void)buf;
}

static void on_write(uv_write_t *req, int status) {
  client_t *client = (client_t *)((uv_handle_t *)req->handle)->data;

  if (status < 0) {
    fprintf(stderr, "Write error: %s\n", uv_err_name(status));
    uv_close((uv_handle_t *)&client->handle, on_close);
    uv_close((uv_handle_t *)&client->timer, on_close);
  } else {
    uv_timer_start(&client->timer, (uv_timer_cb)req->data,
                   INTERVAL_LINE_BANNER_MS, 0);
  }
}

static void on_timer(uv_timer_t *timer) {
  client_t *client = (client_t *)timer->data;

  char line[256];
  int len = randline(line, MAX_LINE_LENGTH, &client->rng_state);

  uv_write_t *req = &client->write_req;
  req->data = (void *)on_timer;

  uv_buf_t buf = uv_buf_init(line, (unsigned int)len);
  int r = uv_write(req, (uv_stream_t *)&client->handle, &buf, 1, on_write);
  if (r < 0) {
    fprintf(stderr, "uv_write failed: %s\n", uv_err_name(r));
    uv_close((uv_handle_t *)&client->handle, on_close);
    uv_close((uv_handle_t *)&client->timer, on_close);
  }
}

static void on_new_connection(uv_stream_t *server, int status) {
  if (status < 0) {
    fprintf(stderr, "New connection error: %s\n", uv_err_name(status));
    return;
  }

  client_t *client = (client_t *)malloc(sizeof(client_t));
  if (!client) {
    fprintf(stderr, "Out of memory for new client\n");
    return;
  }

  memset(client, 0, sizeof(*client));
  strncpy(client->ip_address, "unknown", sizeof(client->ip_address) - 1);
  client->proxy_done = 0;

  uv_tcp_init(uv_default_loop(), &client->handle);
  uv_timer_init(uv_default_loop(), &client->timer);

  client->handle.data = client;
  client->timer.data = client;
  client->refcount = 2;

  if (uv_accept(server, (uv_stream_t *)&client->handle) == 0) {
    struct sockaddr_storage addr;
    int namelen = sizeof(addr);
    if (uv_tcp_getpeername(&client->handle, (struct sockaddr *)&addr,
                           &namelen) == 0) {
      if (addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
        uv_ip4_name(addr_in, client->ip_address, sizeof(client->ip_address));
      } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
        uv_ip6_name(addr_in6, client->ip_address, sizeof(client->ip_address));
      }
    }

    printf("%s connected\n", client->ip_address);

    uv_os_fd_t fd;
    if (uv_fileno((uv_handle_t *)&client->handle, &fd) == 0) {
      int value = 1024;
      setsockopt((int)fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));
      setsockopt((int)fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
    }

    uv_tcp_nodelay(&client->handle, 1);
    uv_read_start((uv_stream_t *)&client->handle, alloc_buffer, on_read);
    uv_timer_start(&client->timer, on_timer, INTERVAL_LINE_BANNER_MS, 0);
  } else {
    uv_close((uv_handle_t *)&client->handle, on_close);
    uv_close((uv_handle_t *)&client->timer, on_close);
  }
}

int main(void) {
  uv_loop_t *loop = uv_default_loop();

  uv_tcp_t server;
  uv_tcp_init(loop, &server);

  struct sockaddr_in6 addr;
  uv_ip6_addr("::", PORT, &addr);
  uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);

  int r = uv_listen((uv_stream_t *)&server, MAX_BACKLOG, on_new_connection);
  if (r) {
    fprintf(stderr, "Listen error: %s\n", uv_err_name(r));
    return 1;
  }

  printf("version %s\n", VERSION_STRING);
  printf("Listening on [::]:%d\n", PORT);
  printf("Listening on 0.0.0.0:%d\n", PORT);

  uv_run(loop, UV_RUN_DEFAULT);

  uv_close((uv_handle_t *)&server, NULL);
  uv_loop_close(loop);
  return 0;
}
