/*-
 * collectd - src/mcelogmon.c
 *
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *   Maryam Tahhan <maryam.tahhan@intel.com>
 *   Volodymyr Mytnyk <volodymyrx.mytnyk@intel.com>
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>

#include "collectd.h"
#include "common.h"

#define MCELOGMON_PLUGIN "mcelogmon"
#define BUFF_SIZE 1024
#define CAN_READ 1
#define CAN_WRITE 2

struct mcelogmon_config_s {
  char socket_path[PATH_MAX];   /* mcelog client socket */
  char logfile[PATH_MAX];       /* mcelog logfile */
  struct sockaddr_un unix_sock; /*mcelog client socket*/
  int sock_fd;
};
typedef struct mcelogmon_config_s mcelogmon_config_t;

mcelogmon_config_t g_mcelog_config;

static int g_configured;

static int check_socket(void);

static void mcelogmon_config_init_default(void) {
  static const char socket_path[] = "/var/run/mcelog-client";
  static const char logfile[] = "/var/log/mcelog";
  memset((void *)&g_mcelog_config, 0, sizeof(mcelogmon_config_t));
  bzero((char *)&g_mcelog_config.unix_sock, sizeof(g_mcelog_config.unix_sock));
  sstrncpy(g_mcelog_config.socket_path, socket_path, sizeof(socket_path));
  sstrncpy(g_mcelog_config.logfile, logfile, sizeof(logfile));
  sstrncpy(g_mcelog_config.unix_sock.sun_path, g_mcelog_config.socket_path,
           sizeof(g_mcelog_config.unix_sock.sun_path) - 1);
  DEBUG("%s: logfile %s", MCELOGMON_PLUGIN, g_mcelog_config.logfile);
  DEBUG("%s: sun_path %s", MCELOGMON_PLUGIN,
        g_mcelog_config.unix_sock.sun_path);
}

static int mcelogmon_config(oconfig_item_t *ci) {
  mcelogmon_config_init_default();
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("McelogClientSocket", child->key) == 0) {
      if (cf_util_get_string_buffer(child, g_mcelog_config.unix_sock.sun_path,
                                    sizeof(g_mcelog_config.unix_sock.sun_path) -
                                        1) < 0) {
        ERROR("%s: Invalid configuration option: \"%s\".", MCELOGMON_PLUGIN,
              child->key);
        return -1;
      }
    } else if (strcasecmp("McelogLogfile", child->key) == 0) {
      if (cf_util_get_string_buffer(child, g_mcelog_config.logfile,
                                    sizeof(g_mcelog_config.logfile)) < 0) {
        ERROR("%s: Invalid configuration option: \"%s\".", MCELOGMON_PLUGIN,
              child->key);
        return -1;
      }
    } else {
      ERROR("%s: Invalid configuration option: \"%s\".", MCELOGMON_PLUGIN,
            child->key);
      return -1;
    }
  }
  g_configured = 1;
  return (0);
}

static int connect_to_client_socket(void) {
  char errbuff[BUFF_SIZE];
  struct timeval socket_timeout;
  cdtime_t interval = plugin_get_interval();
  CDTIME_T_TO_TIMEVAL(interval, &socket_timeout);

  g_mcelog_config.unix_sock.sun_family = AF_UNIX;
  g_mcelog_config.sock_fd = -1;
  g_mcelog_config.sock_fd = socket(PF_UNIX, SOCK_STREAM, 0);

  if (g_mcelog_config.sock_fd < 0) {
    sstrerror(errno, errbuff, sizeof(errbuff));
    ERROR("%s: Could not create a socket. %s", MCELOGMON_PLUGIN, errbuff);
    return -1;
  }

  /*Set socket timeout option*/
  if (setsockopt(g_mcelog_config.sock_fd, SOL_SOCKET, SO_SNDTIMEO,
                 (char *)&socket_timeout, sizeof(socket_timeout)) < 0)
    ERROR("%s: Failed to set the socket timeout option.", MCELOGMON_PLUGIN);

  if (connect(g_mcelog_config.sock_fd,
              (struct sockaddr *)&(g_mcelog_config.unix_sock),
              sizeof(struct sockaddr_un)) < 0) {
    sstrerror(errno, errbuff, sizeof(errbuff));
    ERROR("%s: Failed to connect to mcelog server. %s", MCELOGMON_PLUGIN,
          errbuff);
    close(g_mcelog_config.sock_fd);
    return -1;
  }
  return 0;
}

/* Send all requested data to the socket. Returns 0 if
 * ALL request data has been sent otherwise negative value
 * is returned
 */
static int mcelog_mon_send_data(const char *data, size_t len) {
  ssize_t nbytes = 0;
  size_t rem = len;
  size_t off = 0;
  int ret = check_socket();

  if (ret == CAN_WRITE || ret == 0) {
    while (rem > 0) {
      if ((nbytes = send(g_mcelog_config.sock_fd, data + off, rem,
                         MSG_NOSIGNAL)) <= 0)
        return (-1);
      rem -= (size_t)nbytes;
      off += (size_t)nbytes;
    }
  }
  return (0);
}

static int mcelogmon_init(void) {
  if (!g_configured)
    mcelogmon_config_init_default();
  return connect_to_client_socket();
}

static int check_socket(void) {
  struct pollfd poll_fd;
  int poll_ret = 0;

  poll_fd.fd = g_mcelog_config.sock_fd;
  poll_fd.events = POLLIN | POLLPRI | POLLOUT;
  poll_fd.revents = 0;

  poll_ret = poll(&poll_fd, 1, /* ms */ 1000);
  if (poll_ret > 0) {
    if (poll_fd.revents & POLLNVAL) {
      /* invalid file descriptor, reconnect */
      if (connect_to_client_socket() != 0) {
        ERROR("%s: Failed to connect client socket", MCELOGMON_PLUGIN);
        return -1;
      }
    } else if ((poll_fd.revents & POLLERR) || (poll_fd.revents & POLLHUP)) {
      /* connection is broken */
      close(g_mcelog_config.sock_fd);
      ERROR("%s: Connection to socket is broken", MCELOGMON_PLUGIN);
      return -1;
    } else if ((poll_fd.revents & POLLIN) || (poll_fd.revents & POLLPRI)) {
      return CAN_READ;
    } else if ((poll_fd.revents & POLLOUT)) {
      return CAN_WRITE;
    }
  } else if (poll_ret == 0)
    DEBUG("%s: poll() timeout", MCELOGMON_PLUGIN);
  else {
    ERROR("%s: poll() error", MCELOGMON_PLUGIN);
    return -1;
  }

  return 0;
}

static int ping_server(void) {
  static const char ping[] = "ping\n";
  char buf[BUFF_SIZE] = {0};
  int ret = -1;

  if (mcelog_mon_send_data(ping, sizeof(ping)) != 0)
    return (-1);

  DEBUG("%s: pinged server", MCELOGMON_PLUGIN);

  ret = check_socket();
  if (ret == CAN_READ || ret == 0) {
    if (read(g_mcelog_config.sock_fd, buf, sizeof(buf)) > 0) {
      if (strlen(buf) >= 5 && (strcmp(buf, "pong\n") != 0)) {
        ERROR("%s: Server did not respond to ping", MCELOGMON_PLUGIN);
        return -1;
      }
      DEBUG("%s: Server responded to ping", MCELOGMON_PLUGIN);
    }
  }
  return 0;
}

static void mcelogmon_dispatch_notification(void) {
  notification_t n = {NOTIF_FAILURE, cdtime(), "", "",  MCELOGMON_PLUGIN,
                      "",            "",       "", NULL};
  ssnprintf(n.message, sizeof(n.message),
            "mcelog server did not respond to ping.");
  sstrncpy(n.host, hostname_g, sizeof(n.host));
  sstrncpy(n.type, "gauge", sizeof(n.type));
  sstrncpy(n.type_instance, "mcelog_status", sizeof(n.type_instance));
  plugin_dispatch_notification(&n);
}

static int get_memory_machine_checks(void) {
  char buf[BUFF_SIZE] = {0};
  static const char dump[] = "dump all bios\n";
  int ret = -1;

  if (mcelog_mon_send_data(dump, sizeof(dump)) != 0)
    return (-1);

  DEBUG("%s: SENT DUMP REQUEST", MCELOGMON_PLUGIN);
  ret = check_socket();
  if (ret == CAN_READ || ret == 0) {
    int n = read(g_mcelog_config.sock_fd, buf, sizeof(buf));
    if (n > 0) {
      DEBUG("%s: Server responded, Retrieved INFO %s, read = %d ",
            MCELOGMON_PLUGIN, buf, n);
    } else if (n < 0) {
      ERROR("%s: Can't read from server", MCELOGMON_PLUGIN);
      return -1;
    }
  } /*  if (ret == CAN_READ || ret = 0) */

  return 0;
}

static int mcelogmon_read(__attribute__((unused)) user_data_t *ud) {
  DEBUG("%s: %s", MCELOGMON_PLUGIN, __FUNCTION__);
  if (ping_server() != 0) {
    mcelogmon_dispatch_notification();
  }

  if (get_memory_machine_checks() != 0)
    ERROR("%s: MACHINE CHECK INFO NOT AVAILABLE", MCELOGMON_PLUGIN);

  return 0;
}

static int mcelogmon_shutdown(void) {
  if (unlink(g_mcelog_config.unix_sock.sun_path) != 0) {
    ERROR("%s: Unlinking the socket path", MCELOGMON_PLUGIN);
    return -1;
  }
  close(g_mcelog_config.sock_fd);
  return 0;
}

void module_register(void) {
  plugin_register_complex_config(MCELOGMON_PLUGIN, mcelogmon_config);
  plugin_register_init(MCELOGMON_PLUGIN, mcelogmon_init);
  plugin_register_complex_read(NULL, MCELOGMON_PLUGIN, mcelogmon_read, 0, NULL);
  plugin_register_shutdown(MCELOGMON_PLUGIN, mcelogmon_shutdown);
}
