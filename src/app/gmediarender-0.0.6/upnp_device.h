/* upnp_device.h - Generic UPnP Device handler
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

#ifndef _UPNP_DEVICE_H
#define _UPNP_DEVICE_H

extern int upnp_device_init(struct device *device_def, char *ip_address);


int
upnp_add_response(struct action_event *event, char *key, const char *value);


extern void upnp_set_error(struct action_event *event, int error_code,
			   const char *format, ...);
extern char *upnp_get_string(struct action_event *event, const char *key);
int upnp_append_variable(struct action_event *event,
			 int varnum, char *paramname);

extern UpnpDevice_Handle device_handle;

#endif /* _UPNP_DEVICE_H */
