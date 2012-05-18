/*
 * Copyright (C) 2008 David Gibson.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Sniffing support for the Linux evdev interface.
 * By David Gibson <david () gibson dropbear id au>
 *
 */
#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header$ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"
#include "pcap-evdev-linux.h"

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <byteswap.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/input.h>

#define EVDEV_IFACE            "event"
#define EVDEV_DEV_DIR          "/dev/input"
#define EVDEV_KNOWN_VERSION    0x010001 //Was 0x010000

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htols(s) s
#define htoll(l) l
#define htol64(ll) ll
#else
#define htols(s) bswap_16(s)
#define htoll(l) bswap_32(l)
#define htol64(ll) bswap_64(ll)
#endif

static int evdev_dev_add(pcap_if_t** alldevsp, const char *dev_name, char *err_str)
{
       char dev_descr[30];

       snprintf(dev_descr, 30, "input layer evdev device %s", dev_name);

       if (pcap_add_if(alldevsp, dev_name, 0, dev_descr, err_str) < 0)
               return -1;
       return 0;
}

int evdev_platform_finddevs(pcap_if_t **alldevsp, char *err_str)
{
       struct dirent *data;
       int ret = 0;
       DIR *dir;

       /* scan udev directory */
       dir = opendir(EVDEV_DEV_DIR);
       if (!dir)
               return 0;
       while ((ret == 0) && ((data = readdir(dir)) != 0)) {
               int n;
               char *name = data->d_name;
               int len = strlen(name);

               /* Check if this is an event device */
               if (strncmp(name, EVDEV_IFACE, strlen(EVDEV_IFACE)) != 0)
                       continue;

               ret = evdev_dev_add(alldevsp, name, err_str);
       }

       closedir(dir);
       return ret;
}

static int evdev_inject_linux(pcap_t *handle, const void *buf, size_t size)
{
       snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported on "
                "evdev devices");
       return (-1);
}

static int evdev_setfilter_linux(pcap_t *p, struct bpf_program *fp)
{
       return 0;
}

static int evdev_setdirection_linux(pcap_t *p, pcap_direction_t d)
{
       p->direction = d;
       return 0;
}

static int evdev_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
       stats->ps_recv = handle->md.packets_read;
       stats->ps_ifdrop = 0;
       return 0;
}

static int evdev_read_linux(pcap_t *handle, int max_packets,
                           pcap_handler callback, u_char *user)
{
       int ret;
       struct pcap_pkthdr pkth;
       struct input_event *ie = (struct input_event *)handle->buffer;

       ret = read(handle->fd, handle->buffer, sizeof(struct input_event));
       if (ret < 0) {
               snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
                        "Can't read from fd %d: %s", handle->fd, strerror(errno));
               return -1;
       }
       if (ret < sizeof(struct input_event)) {
               snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
                        "Short read from fd %d: %d of %d bytes",
                        handle->fd, ret, sizeof(struct input_event));
               return -1;
       }

       pkth.caplen = pkth.len = sizeof(struct input_event);
       if (handle->snapshot < pkth.caplen)
               pkth.caplen = handle->snapshot;
       pkth.ts = ie->time;

       handle->md.packets_read++;
       callback(user, &pkth, handle->buffer);
       return 1;
}

static int evdev_activate(pcap_t *handle)
{
       char evdev_path[PATH_MAX];
       int evdev_version;
       int err;

       /* Initialize some components of the pcap structure. */
       handle->bufsize = sizeof(struct input_event);
       handle->offset = 0;
       handle->linktype = DLT_LINUX_EVDEV;

       handle->inject_op = evdev_inject_linux;
       handle->setfilter_op = evdev_setfilter_linux;
       handle->setdirection_op = evdev_setdirection_linux;
       handle->set_datalink_op = NULL; /* can't change data link type */
       handle->getnonblock_op = pcap_getnonblock_fd;
       handle->setnonblock_op = pcap_setnonblock_fd;

       /* get index from device name */
       if (sscanf(handle->opt.source, EVDEV_IFACE"%d", &handle->md.ifindex) != 1) {
               snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
                       "Can't get USB bus index from %s", handle->opt.source);
               return PCAP_ERROR;
       }

       snprintf(evdev_path, PATH_MAX, EVDEV_DEV_DIR "/%s", handle->opt.source);
       handle->fd = open(evdev_path, O_RDONLY, 0);
       if (handle->fd < 0) {
               snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
                        "Can't open evdev device %s: %s", evdev_path,
                        strerror(errno));
               return PCAP_ERROR;
       }

       err = ioctl(handle->fd, EVIOCGVERSION, &evdev_version);
       if (err < 0) {
               snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
                        "EVIOCGVERSION failed (%s), looks like %s isn't an evdev",
                        strerror(errno), evdev_path);
               return PCAP_ERROR;
       }

       if (evdev_version != EVDEV_KNOWN_VERSION) {
               snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
                        "Don't understand evdev protocol version 0x%06x",
                        evdev_version);
               return PCAP_ERROR;
       }

       if (handle->opt.rfmon)
               /* Monitor mode doesn't apply to evdev devices. */
               return PCAP_ERROR_RFMON_NOTSUP;

       handle->stats_op = evdev_stats_linux;
       handle->read_op = evdev_read_linux;

       /*
        * "handle->fd" is a real file, so "select()" and "poll()"
        * work on it.
        */
       handle->selectable_fd = handle->fd;

       handle->buffer = malloc(handle->bufsize);
       if (!handle->buffer) {
               snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
                        "malloc: %s", pcap_strerror(errno));
               return PCAP_ERROR;
       }
       return 0;
}

pcap_t *evdev_create(const char *device, char *ebuf)
{
       pcap_t *p;

       p = pcap_create_common(device, ebuf);
       if (p == NULL)
               return (NULL);

       p->activate_op = evdev_activate;
       return (p);
}
