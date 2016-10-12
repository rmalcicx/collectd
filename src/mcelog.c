/*-
 * collectd - src/mcelog.c
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
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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
 *   Taras Chornyi <tarasx.chornyi@intel.com>
 */

#include "common.h"
#include "collectd.h"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MCELOG_PLUGIN "mcelog"
#define BUFF_SIZE 1024
#define POLL_TIMEOUT 1000 /* ms */

struct mcelog_config_s {
  char socket_path[PATH_MAX];   /* mcelog client socket */
  char logfile[PATH_MAX];       /* mcelog logfile */
  struct sockaddr_un unix_sock; /* mcelog client socket */
  pthread_t tid;                /* poll thread id */
  int sock_fd;                  /* mcelog server socket fd */
};

struct mcelog_memory_rec_s {
  char location[DATA_MAX_NAME_LEN];  /* SOCKET x CHANNEL x DIMM x*/
  char dimm_name[DATA_MAX_NAME_LEN]; /* DMI_NAME "DIMM_F1" */
  int corrected_err_total;           /* x total*/
  int corrected_err_timed;           /* x in 24h*/
  char corrected_err_timed_period[DATA_MAX_NAME_LEN];
  int uncorrected_err_total; /* x total*/
  int uncorrected_err_timed; /* x in 24h*/
  char uncorrected_err_timed_period[DATA_MAX_NAME_LEN];
};

typedef struct mcelog_config_s mcelog_config_t;
typedef struct mcelog_memory_rec_s mcelog_memory_rec_t;

mcelog_config_t g_mcelog_config;

static int g_configured;
static _Bool mcelog_thread_shutdown = 0;
static pthread_mutex_t mcelog_thread_lock = PTHREAD_MUTEX_INITIALIZER;

static const char socket_str[] = "SOCKET";
static const char dimm_name[] = "DMI_NAME";
static const char corrected_err[] = "corrected memory errors:";
static const char uncorrected_err[] = "uncorrected memory errors:";

static void mcelog_config_init_default(void) {
  static const char socket_path[] = "/var/run/mcelog-client";
  static const char logfile[] = "/var/log/mcelog";
  memset((void *)&g_mcelog_config, 0, sizeof(mcelog_config_t));
  bzero((char *)&g_mcelog_config.unix_sock, sizeof(g_mcelog_config.unix_sock));
  sstrncpy(g_mcelog_config.socket_path, socket_path, sizeof(socket_path));
  sstrncpy(g_mcelog_config.logfile, logfile, sizeof(logfile));
  sstrncpy(g_mcelog_config.unix_sock.sun_path, g_mcelog_config.socket_path,
           sizeof(g_mcelog_config.unix_sock.sun_path) - 1);
  DEBUG("%s: logfile %s", MCELOG_PLUGIN, g_mcelog_config.logfile);
  DEBUG("%s: sun_path %s", MCELOG_PLUGIN, g_mcelog_config.unix_sock.sun_path);
}

static int mcelog_config(oconfig_item_t *ci) {
  mcelog_config_init_default();
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("McelogClientSocket", child->key) == 0) {
      if (cf_util_get_string_buffer(child, g_mcelog_config.unix_sock.sun_path,
                                    sizeof(g_mcelog_config.unix_sock.sun_path) -
                                        1) < 0) {
        ERROR("%s: Invalid configuration option: \"%s\".", MCELOG_PLUGIN,
              child->key);
        return -1;
      }
    } else if (strcasecmp("McelogLogfile", child->key) == 0) {
      if (cf_util_get_string_buffer(child, g_mcelog_config.logfile,
                                    sizeof(g_mcelog_config.logfile)) < 0) {
        ERROR("%s: Invalid configuration option: \"%s\".", MCELOG_PLUGIN,
              child->key);
        return -1;
      }
    } else {
      ERROR("%s: Invalid configuration option: \"%s\".", MCELOG_PLUGIN,
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
    ERROR("%s: Could not create a socket. %s", MCELOG_PLUGIN, errbuff);
    return -1;
  }

  /*Set socket timeout option*/
  if (setsockopt(g_mcelog_config.sock_fd, SOL_SOCKET, SO_SNDTIMEO,
                 (char *)&socket_timeout, sizeof(socket_timeout)) < 0)
    ERROR("%s: Failed to set the socket timeout option.", MCELOG_PLUGIN);

  if (connect(g_mcelog_config.sock_fd,
              (struct sockaddr *)&(g_mcelog_config.unix_sock),
              sizeof(struct sockaddr_un)) < 0) {
    sstrerror(errno, errbuff, sizeof(errbuff));
    ERROR("%s: Failed to connect to mcelog server. %s", MCELOG_PLUGIN, errbuff);
    shutdown(g_mcelog_config.sock_fd, 0);

    return -1;
  }
  return 0;
}

static void mcelog_dispatch_notification(notification_t n) {
  sstrncpy(n.host, hostname_g, sizeof(n.host));
  sstrncpy(n.type, "gauge", sizeof(n.type));
  plugin_dispatch_notification(&n);
}

static int mcelog_prepare_notification(notification_t *n,
                                       mcelog_memory_rec_t mr) {

  if (n == NULL)
    return (-1);

  if (plugin_notification_meta_add_string(n, socket_str, mr.location) < 0) {
    ERROR("%s: add memory location meta data failed", MCELOG_PLUGIN);
    return (-1);
  }
  if (strlen(mr.dimm_name) > 0)
    if (plugin_notification_meta_add_string(n, dimm_name, mr.dimm_name) < 0) {
      ERROR("%s: add DIMM name meta data failed", MCELOG_PLUGIN);
      return (-1);
    }
  if (plugin_notification_meta_add_signed_int(n, corrected_err,
                                              mr.corrected_err_total) < 0) {
    ERROR("%s: add corrected errors meta data failed", MCELOG_PLUGIN);
    return (-1);
  }
  if (plugin_notification_meta_add_signed_int(
          n, "corrected memory timed errors", mr.corrected_err_timed) < 0) {
    ERROR("%s: add corrected timed errors meta data failed", MCELOG_PLUGIN);
    return (-1);
  }
  if (plugin_notification_meta_add_string(n, "corrected errors time period",
                                          mr.corrected_err_timed_period) < 0) {
    ERROR("%s: add corrected errors period meta data failed", MCELOG_PLUGIN);
    return (-1);
  }
  if (plugin_notification_meta_add_signed_int(n, uncorrected_err,
                                              mr.uncorrected_err_total) < 0) {
    ERROR("%s: add corrected errors meta data failed", MCELOG_PLUGIN);
    return (-1);
  }
  if (plugin_notification_meta_add_signed_int(
          n, "uncorrected memory timed errors", mr.uncorrected_err_timed) < 0) {
    ERROR("%s: add corrected timed errors meta data failed", MCELOG_PLUGIN);
    return (-1);
  }
  if (plugin_notification_meta_add_string(n, "uncorrected errors time period",
                                          mr.uncorrected_err_timed_period) <
      0) {
    ERROR("%s: add corrected errors period meta data failed", MCELOG_PLUGIN);
    return (-1);
  }

  return (0);
}

static int mcelog_submit(mcelog_memory_rec_t mr) {

  value_list_t vl = VALUE_LIST_INIT;
  char type_instance[DATA_MAX_NAME_LEN] = {0};
  char plugin_instance[DATA_MAX_NAME_LEN] = {0};
  vl.values_len = 1;
  vl.time = cdtime();

  sstrncpy(vl.plugin, MCELOG_PLUGIN, sizeof(vl.plugin));
  sstrncpy(vl.type, "errors", sizeof(vl.type));
  if (strlen(mr.dimm_name) > 0) {
    snprintf(plugin_instance, DATA_MAX_NAME_LEN, "%s_%s", mr.location,
             mr.dimm_name);
    sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  } else
    sstrncpy(vl.plugin_instance, mr.location, sizeof(vl.plugin_instance));

  sstrncpy(vl.type_instance, "corrected_memory_errors",
           sizeof(vl.type_instance));
  vl.values = &(value_t){.derive = (derive_t)mr.corrected_err_total};
  plugin_dispatch_values(&vl);

  snprintf(type_instance, DATA_MAX_NAME_LEN, "corrected_memory_errors_in_%s",
           mr.corrected_err_timed_period);
  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));
  vl.values = &(value_t){.derive = (derive_t)mr.corrected_err_total};
  plugin_dispatch_values(&vl);

  sstrncpy(vl.type_instance, "uncorrected_memory_errors",
           sizeof(vl.type_instance));
  vl.values = &(value_t){.derive = (derive_t)mr.uncorrected_err_total};
  plugin_dispatch_values(&vl);

  snprintf(type_instance, DATA_MAX_NAME_LEN, "uncorrected_memory_errors_in_%s",
           mr.uncorrected_err_timed_period);
  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));
  vl.values = &(value_t){.derive = (derive_t)mr.uncorrected_err_total};
  plugin_dispatch_values(&vl);

  return 0;
}

static void *poll_worker(__attribute__((unused)) void *arg) {
  char buf[DATA_MAX_NAME_LEN] = {0};
  mcelog_memory_rec_t memory_record;
  _Bool received_data = 0;
  FILE *p_file;

  struct pollfd poll_fd = {
      .fd = g_mcelog_config.sock_fd, .events = POLLIN | POLLPRI,
  };

  while (1) {

    pthread_mutex_lock(&mcelog_thread_lock);
    if (mcelog_thread_shutdown == 1) {
      pthread_mutex_unlock(&mcelog_thread_lock);
      pthread_exit(NULL);
    }
    pthread_mutex_unlock(&mcelog_thread_lock);
    int poll_ret = poll(&poll_fd, 1, POLL_TIMEOUT);

    if (poll_ret > 0) {
      if (poll_fd.revents & POLLNVAL) {
        if (connect_to_client_socket() != 0)
          usleep(POLL_TIMEOUT);
      }
      if ((poll_fd.revents & POLLERR) || (poll_fd.revents & POLLHUP)) {
        /* connection is broken */
        shutdown(g_mcelog_config.sock_fd, 0);
        ERROR("%s: Connection to socket is broken", MCELOG_PLUGIN);
        notification_t n = {
            NOTIF_FAILURE, cdtime(), "", "", MCELOG_PLUGIN, "", "", "", NULL};
        ssnprintf(n.message, sizeof(n.message),
                  "Connection to mcelog socket is broken.");
        sstrncpy(n.type_instance, "mcelog_status", sizeof(n.type_instance));
        mcelog_dispatch_notification(n);
        break;
      }
      if ((poll_fd.revents & POLLIN) || (poll_fd.revents & POLLPRI)) {
        if ((p_file = fdopen(dup(g_mcelog_config.sock_fd), "r")) != NULL) {
          memset(buf, 0, sizeof(buf));
          while (fgets(buf, sizeof(buf), p_file)) {
            /* Got empty line or "done" */
            if ((strlen(buf) == 1) ||
                ((strlen(buf) >= 5) && (!strcmp(buf, "done\n")))) {
              if (!received_data) {
                break;
              } else {
                notification_t n = {NOTIF_OKAY,    cdtime(), "", "",
                                    MCELOG_PLUGIN, "",       "", "",
                                    NULL};
                ssnprintf(n.message, sizeof(n.message),
                          "Got memory errors info.");
                sstrncpy(n.type_instance, "memory_erros",
                         sizeof(n.type_instance));

                if (mcelog_prepare_notification(&n, memory_record) == 0)
                  mcelog_dispatch_notification(n);
                if (mcelog_submit(memory_record) != 0)
                  ERROR("%s: Failed to submit memory errors", MCELOG_PLUGIN);
                memset(&memory_record, 0, sizeof(memory_record));
              }
            }
            if (strlen(buf) >= 5) {
              if (!strcmp(buf, "done\n")) {
                DEBUG("%s: done", MCELOG_PLUGIN);
                break;
              }
              if (!memcmp(buf, socket_str, strlen(socket_str))) {
                sstrncpy(memory_record.location, buf, strlen(buf));
                /* replace spaces with '_' */
                for (size_t i = 0; i < strlen(memory_record.location); i++)
                  if (memory_record.location[i] == ' ')
                    memory_record.location[i] = '_';
                received_data = 1;
                DEBUG("%s: Got SOCKET INFO %s", MCELOG_PLUGIN,
                      memory_record.location);
              }
              if (!memcmp(buf, dimm_name, strlen(dimm_name))) {
                char *name = NULL;
                char *saveptr = NULL;
                name = strtok_r(buf, "\"", &saveptr);
                if (name != NULL && saveptr != NULL) {
                    name = strtok_r(NULL, "\"", &saveptr);
                    if (name != NULL ) {
                      sstrncpy(memory_record.dimm_name, name,
                               sizeof(memory_record.dimm_name));
                      DEBUG("%s: Got DIMM NAME %s", MCELOG_PLUGIN,
                            memory_record.dimm_name);
                    }
                }
              }
              if (!memcmp(buf, corrected_err, strlen(corrected_err))) {
                /* Get next line*/
                if (fgets(buf, sizeof(buf), p_file) != NULL) {
                  sscanf(buf, "\t%d total", &memory_record.corrected_err_total);
                  DEBUG("%s: Got corrected error total %d", MCELOG_PLUGIN,
                        memory_record.corrected_err_total);
                }
                if (fgets(buf, sizeof(buf), p_file) != NULL) {
                  sscanf(buf, "\t%d in %s", &memory_record.corrected_err_timed,
                         memory_record.corrected_err_timed_period);
                  DEBUG("%s: Got timed corrected errors %d in %s",
                        MCELOG_PLUGIN, memory_record.corrected_err_total,
                        memory_record.corrected_err_timed_period);
                }
              }
              if (!memcmp(buf, uncorrected_err, strlen(uncorrected_err))) {
                if (fgets(buf, sizeof(buf), p_file) != NULL) {
                  sscanf(buf, "\t%d total",
                         &memory_record.uncorrected_err_total);
                  DEBUG("%s: Got uncorrected error total %d", MCELOG_PLUGIN,
                        memory_record.uncorrected_err_total);
                }
                if (fgets(buf, sizeof(buf), p_file) != NULL) {
                  sscanf(buf, "\t%d in %s",
                         &memory_record.uncorrected_err_timed,
                         memory_record.uncorrected_err_timed_period);
                  DEBUG("%s: Got timed uncorrected errors %d in %s",
                        MCELOG_PLUGIN, memory_record.uncorrected_err_total,
                        memory_record.uncorrected_err_timed_period);
                }
              }
            }
          }
          fclose(p_file);
        }
      }
    }
  }
  return NULL;
}

static int mcelog_init(void) {
  if (!g_configured)
    mcelog_config_init_default();

  if (connect_to_client_socket() != 0) {
    ERROR("%s: Cannot connect to client socket", MCELOG_PLUGIN);
    return -1;
  }

  if (plugin_thread_create(&g_mcelog_config.tid, NULL, poll_worker, NULL) !=
      0) {
    ERROR("%s: Error creating poll thread.", MCELOG_PLUGIN);
    return -1;
  }
  return 0;
}

static int get_memory_machine_checks(void) {
  static const char dump[] = "dump all bios\n";

  if (swrite(g_mcelog_config.sock_fd, dump, sizeof(dump)) < 0)
    return (-1);

  DEBUG("%s: SENT DUMP REQUEST", MCELOG_PLUGIN);
  return 0;
}

static int mcelog_read(__attribute__((unused)) user_data_t *ud) {
  DEBUG("%s: %s", MCELOG_PLUGIN, __FUNCTION__);

  if (get_memory_machine_checks() != 0)
    ERROR("%s: MACHINE CHECK INFO NOT AVAILABLE", MCELOG_PLUGIN);

  return 0;
}

static int mcelog_shutdown(void) {
  pthread_mutex_lock(&mcelog_thread_lock);
  mcelog_thread_shutdown = 1;
  pthread_mutex_unlock(&mcelog_thread_lock);
  pthread_join(g_mcelog_config.tid, NULL);
  pthread_mutex_destroy(&mcelog_thread_lock);
  shutdown(g_mcelog_config.sock_fd, 0);
  return 0;
}

void module_register(void) {
  plugin_register_complex_config(MCELOG_PLUGIN, mcelog_config);
  plugin_register_init(MCELOG_PLUGIN, mcelog_init);
  plugin_register_complex_read(NULL, MCELOG_PLUGIN, mcelog_read, 0, NULL);
  plugin_register_shutdown(MCELOG_PLUGIN, mcelog_shutdown);
}
