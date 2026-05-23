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
#define VERSION_MINOR 2
#define VERSION_PATCH 0

#define STRINGIFY0(x) #x
#define STRINGIFY(x) STRINGIFY0(x)

#define VERSION_STRING                                                         \
  STRINGIFY(VERSION_MAJOR)                                                     \
  "." STRINGIFY(VERSION_MINOR) "." STRINGIFY(VERSION_PATCH)

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
/**
 * The maximum length of the queue for pending connections (passed directly to
 * the OS listen() syscall). If more connections arrive than the backlog can
 * hold, the OS silently drops or rejects them.
 **/
#define MAX_BACKLOG 64

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
  uv_write_t write_req; /* reused for every banner */
  char read_buf[READ_BUFFER_SIZE];
  unsigned long rng_state; /* per‑client RNG */
} client_t;

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size,
                         uv_buf_t *buf) {
  client_t *client = (handle->data);
  buf->base = client->read_buf;
  buf->len = sizeof(client->read_buf);
  (void)suggested_size;
}

static void on_close(uv_handle_t *handle) {
  client_t *client = (client_t *)handle->data;
  if (--client->refcount == 0) {
    free(client);
    printf("Client connection closed\n");
  }
}

static void on_read(uv_stream_t *client_stream, ssize_t nread,
                    const uv_buf_t *buf) {
  (void)buf;
  uv_handle_t *handle = (uv_handle_t *)client_stream;
  client_t *client = (client_t *)handle->data;

  if (nread < 0) {
    if (nread != UV_EOF) {
      fprintf(stderr, "Client read error: %s\n", uv_err_name(nread));
    }
    /* Close both handle and timer */
    uv_close((uv_handle_t *)&client->handle, on_close);
    uv_close((uv_handle_t *)&client->timer, on_close);
  }
}

static void on_write(uv_write_t *req, int status) {
  client_t *client = (client_t *)((uv_handle_t *)req->handle)->data;

  if (status < 0) {
    fprintf(stderr, "Write error: %s\n", uv_err_name(status));
    uv_close((uv_handle_t *)&client->handle, on_close);
    uv_close((uv_handle_t *)&client->timer, on_close);
  } else {
    /* Schedule next random banner after DELAY */
    uv_timer_start(&client->timer, (uv_timer_cb)req->data,
                   INTERVAL_LINE_BANNER_MS, 0);
  }
}

/* Timer callback: send one random banner line */
static void on_timer(uv_timer_t *timer) {
  client_t *client = (client_t *)timer->data;

  char line[256];
  int len = randline(line, MAX_LINE_LENGTH, &client->rng_state);

  uv_write_t *req = &client->write_req;
  /* Store timer callback pointer so on_write can restart the timer */
  req->data = (void *)on_timer;

  uv_buf_t buf = uv_buf_init(line, (unsigned int)len);
  int r = uv_write(req, (uv_stream_t *)&client->handle, &buf, 1, on_write);
  if (r < 0) {
    fprintf(stderr, "uv_write failed: %s\n", uv_err_name(r));
    uv_close((uv_handle_t *)&client->handle, on_close);
    uv_close((uv_handle_t *)&client->timer, on_close);
  }
}

/* New connection callback */
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

  uv_tcp_init(uv_default_loop(), &client->handle);
  uv_timer_init(uv_default_loop(), &client->timer);

  client->handle.data = client;
  client->timer.data = client;
  client->refcount = 2;

  if (uv_accept(server, (uv_stream_t *)&client->handle) == 0) {
    printf("Client connected\n");

    /* Set receive buffer within the bounds of TCP MTU (~1500 bytes) */
    uv_os_fd_t fd;
    if (uv_fileno((uv_handle_t *)&client->handle, &fd) == 0) {
      int value = 1024;
      setsockopt((int)fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));
      setsockopt((int)fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
    }

    /*
     * Prevents the Nagle algorithm from adding unnecessary latency
     * See, https://grokipedia.com/page/nagle
     */
    uv_tcp_nodelay(&client->handle, 1);

    /* Start reading immediately to consume and discard data */
    uv_read_start((uv_stream_t *)&client->handle, alloc_buffer, on_read);

    /* Schedule first banner line after initial DELAY */
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

  /* IPv4, IPv6 dual-stack bind */
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
  printf("Press Ctrl+C to stop.\n");

  uv_run(loop, UV_RUN_DEFAULT);

  /* Cleanup */
  uv_close((uv_handle_t *)&server, NULL);
  uv_loop_close(loop);
  return 0;
}
