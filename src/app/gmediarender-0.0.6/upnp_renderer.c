/* upnp_renderer.c - UPnP renderer routines
 *
 * Copyright (C) 2005-2007   Ivo Clarysse
 *
 * This file is part of GMediaRender.
 *
 * GMediaRender is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GMediaRender is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GMediaRender; if not, write to the Free Software 
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
 * MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wm_config.h"

#if TLS_CONFIG_DLNA

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
//#include <unistd.h>
//#include <errno.h>
//#include <stdarg.h>

//#include <sys/types.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>

#include <upnp.h>
#include <ithread.h>
#include <upnptools.h>

#include "logging.h"
#include "upnp_webserver.h"
#include "upnp_if.h"
#include "upnp_device.h"
#include "upnp_connmgr.h"
#include "upnp_control.h"
#include "upnp_transport.h"

#include "upnp_renderer.h"
#include "autoconfig.h"

static struct service *upnp_services[] = {
	&transport_service,
	&connmgr_service,
	&control_service,
	NULL
};

/*static struct icon icon1 = {
        .width =        64,
        .height =       64,
        .depth =        24,
        .url =          "/upnp/grender-64x64.png",
        .mimetype =     "image/png"
};
static struct icon icon2 = {
        .width =        128,
        .height =       128,
        .depth =        24,
        .url =          "/upnp/grender-128x128.png",
        .mimetype =     "image/png"
};*/

static struct icon *renderer_icon[] = {
        //&icon1,
        //&icon2,
        NULL
};

static int upnp_renderer_init(void);

static struct device render_device = {
	.init_function          = upnp_renderer_init,
        .device_type            = "urn:schemas-upnp-org:device:MediaRenderer:1",
        .friendly_name          = "GMediaRender",
        .manufacturer           = "Ivo Clarysse",
        .manufacturer_url       = "http://gmrender.nongnu.org/",
        .model_description      = PACKAGE_STRING,
        .model_name             = PACKAGE_NAME,
        .model_number           = PACKAGE_VERSION,
        .model_url              = "http://gmrender.nongnu.org/",
        .serial_number          = "1",
        .udn                    = "uuid:GMediaRender-1_0-000-000-002",
        .upc                    = "",
        .presentation_url       = "/renderpres.html",
        .icons                  = renderer_icon,
        .services               = upnp_services
};
#if 0
void upnp_renderer_dump_connmgr_scpd(void)
{
	fputs(upnp_get_scpd(&connmgr_service), stdout);
}
void upnp_renderer_dump_control_scpd(void)
{
	fputs(upnp_get_scpd(&control_service), stdout);
}
void upnp_renderer_dump_transport_scpd(void)
{
	fputs(upnp_get_scpd(&transport_service), stdout);
}
#endif
static int upnp_renderer_init(void)
{
	int i;
	struct service *srv = NULL;
	ithread_mutex_init(&render_device.device_mutex, NULL);
	for (i=0; render_device.services[i]; i++) {
		srv = render_device.services[i];
		ithread_mutex_init(srv->service_mutex, NULL);
	}
	return connmgr_init();
}

struct device *upnp_renderer_new(const char *friendly_name,
                                 const char *uuid)
{
	ENTER();
	char *udn;

	render_device.friendly_name = strdup(friendly_name);
	udn = tls_mem_alloc(strlen(uuid)+6);
	sprintf(udn, "uuid:%s", uuid);
	render_device.udn = udn;
	return &render_device;
}

void upnp_renderer_destroy(void)
{
	int i;
	struct service *srv = NULL;
	ENTER();
	ithread_mutex_destroy(&render_device.device_mutex);
	for (i=0; render_device.services[i]; i++) {
		srv = render_device.services[i];
		if(*(srv->service_mutex))
		{
			ithread_mutex_destroy(srv->service_mutex);
			*(srv->service_mutex) = NULL; 
		}
	}
	connmgr_destroy();
	if(render_device.friendly_name)
	{
		tls_mem_free(render_device.friendly_name);
		render_device.friendly_name = NULL;
	}
	if(render_device.udn)
	{
		tls_mem_free(render_device.udn);
		render_device.udn = NULL;
	}
}
#endif

