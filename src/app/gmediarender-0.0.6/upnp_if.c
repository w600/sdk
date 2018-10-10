/* upnp.c - Generic UPnP routines
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
//#include <unistd.h>
//#include <errno.h>
//#include <stdarg.h>
#include "md5.h"
#include "wm_flash.h"
#include <ixml.h>
#include <ithread.h>

#include "upnpdebug.h"
#include "logging.h"

#include "upnp_if.h"

static const char *param_datatype_names[] = {
        [DATATYPE_STRING] =     "string",
        [DATATYPE_BOOLEAN] =    "boolean",
        [DATATYPE_I2] =         "i2",
        [DATATYPE_I4] =         "i4",
        [DATATYPE_UI2] =        "ui2",
        [DATATYPE_UI4] =        "ui4",
        [DATATYPE_UNKNOWN] =    NULL
};

static void add_value_attribute(IXML_Document *doc, IXML_Element *parent,
                                char *attrname, char *value)
{
	ixmlElement_setAttribute(parent, attrname, value);
}

static void add_value_element(IXML_Document *doc, IXML_Element *parent,
                              char *tagname, char *value)
{
	IXML_Element *top;
	IXML_Node *child;

	top=ixmlDocument_createElement(doc, tagname);
	child=ixmlDocument_createTextNode(doc, value);

	ixmlNode_appendChild((IXML_Node *)top,(IXML_Node *)child);

	ixmlNode_appendChild((IXML_Node *)parent,(IXML_Node *)top);
}
static void add_value_element_int(IXML_Document *doc, IXML_Element *parent,
                                  char *tagname, int value)
{
	char *buf;
	buf = tls_mem_alloc(sizeof(int));
	sprintf(buf,"%d",value);
	add_value_element(doc, parent, tagname, buf);
	tls_mem_free(buf);
}
static void add_value_element_long(IXML_Document *doc, IXML_Element *parent,
                                  char *tagname, long long value)
{
	char *buf;
	buf = tls_mem_alloc(sizeof(long long));
	sprintf(buf,"%d",(long)value);
	add_value_element(doc, parent, tagname, buf);
	tls_mem_free(buf);
}

static IXML_Element *gen_specversion(IXML_Document *doc, int major, int minor)
{
	IXML_Element *top;

	top=ixmlDocument_createElement(doc, "specVersion");

	add_value_element_int(doc, top, "major", major);
	add_value_element_int(doc, top, "minor", minor);

	return top;
}

static IXML_Element *gen_scpd_action(IXML_Document *doc, struct action *act,
                                     struct argument **arglist,
                                     const char **varnames)
{
	IXML_Element *top;
	IXML_Element *parent,*child;

	top=ixmlDocument_createElement(doc, "action");

	add_value_element(doc, top, "name", (char *)act->action_name);
	if (arglist) {
		struct argument *arg;
		int j;
		parent=ixmlDocument_createElement(doc, "argumentList");
		ixmlNode_appendChild((IXML_Node *)top,(IXML_Node *)parent);
		for(j=0; (arglist[j]); j++) {
			arg=arglist[j];
			child=ixmlDocument_createElement(doc, "argument");
			ixmlNode_appendChild((IXML_Node *)parent,(IXML_Node *)child);
			add_value_element(doc,child,"name",(char *)arg->name);
			add_value_element(doc,child,"direction",(arg->direction==PARAM_DIR_IN)?"in":"out");
			add_value_element(doc,child,"relatedStateVariable",(char *)varnames[arg->statevar]);
		}
	}
	return top;
}
#if 0
static IXML_Element *gen_scpd_actionlist(IXML_Document *doc,
                                         struct service *srv)
{
	IXML_Element *top;
	IXML_Element *child;
	int i;

	top=ixmlDocument_createElement(doc, "actionList");
	for(i=0; i<srv->command_count; i++) {
		struct action *act;
		struct argument **arglist;
		const char **varnames;
		act=&(srv->actions[i]);
		arglist=srv->action_arguments[i];
		varnames=srv->variable_names;
		if (act) {
			child=gen_scpd_action(doc, act, arglist, varnames);
			ixmlNode_appendChild((IXML_Node *)top,(IXML_Node *)child);
		}
	}
	return top;
}
#endif
static IXML_Element *gen_scpd_statevar(IXML_Document *doc, const char *name, struct var_meta *meta)
{
	IXML_Element *top,*parent;
	const char **valuelist;
	const char *default_value;
	struct param_range *range;

	valuelist = meta->allowed_values;
	range = meta->allowed_range;
	default_value = meta->default_value;


	top=ixmlDocument_createElement(doc, "stateVariable");

	add_value_attribute(doc, top, "sendEvents",(meta->sendevents==SENDEVENT_YES)?"yes":"no");
	add_value_element(doc,top,"name",(char *)name);
	add_value_element(doc,top,"dataType",(char *)param_datatype_names[meta->datatype]);

	if (valuelist) {
		const char *allowed_value;
		int i;
		parent=ixmlDocument_createElement(doc, "allowedValueList");
		ixmlNode_appendChild((IXML_Node *)top,(IXML_Node *)parent);
		for(i=0; (valuelist[i]); i++) {
			allowed_value=valuelist[i];
			add_value_element(doc,parent,"allowedValue",(char *)allowed_value);
		} 
	}
	if (range) {
		parent=ixmlDocument_createElement(doc, "allowedValueRange");
		ixmlNode_appendChild((IXML_Node *)top,(IXML_Node *)parent);
		add_value_element_long(doc,parent,"minimum",range->min);
		add_value_element_long(doc,parent,"maximum",range->max);
		if (range->step != 0L) {
			add_value_element_long(doc,parent,"step",range->step);
		}
	}
	if (default_value) {
		add_value_element(doc,top,"defaultValue",(char *)default_value);
	}
	return top;
}
#if 0
static IXML_Element *gen_scpd_servicestatetable(IXML_Document *doc, struct service *srv)
{
	IXML_Element *top;
	IXML_Element *child;
	int i;

	top=ixmlDocument_createElement(doc, "serviceStateTable");
	for(i=0; i<srv->variable_count; i++) {
		struct var_meta *meta = &(srv->variable_meta[i]);
		const char *name = srv->variable_names[i];
		child=gen_scpd_statevar(doc,name,meta);
		ixmlNode_appendChild((IXML_Node *)top,(IXML_Node *)child);
	}
	return top;
}

static IXML_Document *generate_scpd(struct service *srv)
{
	IXML_Document *doc;
	IXML_Element *root;
	IXML_Element *child;

	doc = ixmlDocument_createDocument();

	root=ixmlDocument_createElementNS(doc, "urn:schemas-upnp-org:service-1-0","scpd");
	ixmlElement_setAttribute(root, "xmlns", "urn:schemas-upnp-org:service-1-0");
	ixmlNode_appendChild((IXML_Node *)doc,(IXML_Node *)root);

	child=gen_specversion(doc,1,0);
	ixmlNode_appendChild((IXML_Node *)root,(IXML_Node *)child);

	child=gen_scpd_actionlist(doc,srv);
	ixmlNode_appendChild((IXML_Node *)root,(IXML_Node *)child);

	child=gen_scpd_servicestatetable(doc,srv);
	ixmlNode_appendChild((IXML_Node *)root,(IXML_Node *)child);
	
	
	return doc;
}

static IXML_Element *gen_desc_iconlist(IXML_Document *doc, struct icon **icons)
{
	IXML_Element *top;
	IXML_Element *parent;
	struct icon *icon_entry;
	int i;

	top=ixmlDocument_createElement(doc, "iconList");

	for (i=0; (icons[i]); i++) {
		icon_entry=icons[i];
		parent=ixmlDocument_createElement(doc, "icon");
		ixmlNode_appendChild((IXML_Node *)top,(IXML_Node *)parent);
		add_value_element(doc,parent,"mimetype",(char *)icon_entry->mimetype);
		add_value_element_int(doc,parent,"width",icon_entry->width);
		add_value_element_int(doc,parent,"height",icon_entry->height);
		add_value_element_int(doc,parent,"depth",icon_entry->depth);
		add_value_element(doc,parent,"url",(char *)icon_entry->url);
	}

	return top;
}
#endif

static IXML_Element *gen_desc_servicelist(struct device *device_def,
                                          IXML_Document *doc)
{
	int i;
	struct service *srv;
	IXML_Element *top;
	IXML_Element *parent;

	top=ixmlDocument_createElement(doc, "serviceList");

        for (i=0; (device_def->services[i]); i++) {
		srv = device_def->services[i];
		parent=ixmlDocument_createElement(doc, "service");
		ixmlNode_appendChild((IXML_Node *)top,(IXML_Node *)parent);
		add_value_element(doc,parent,"serviceType",srv->type);
		add_value_element(doc,parent,"serviceId",(char *)srv->service_name);
		add_value_element(doc,parent,"SCPDURL",(char *)srv->scpd_url);
		add_value_element(doc,parent,"controlURL",(char *)srv->control_url);
		add_value_element(doc,parent,"eventSubURL",(char *)srv->event_url);
        }

	return top;
}


static IXML_Document *generate_desc(struct device *device_def)
{
	IXML_Document *doc;
	IXML_Element *root;
	IXML_Element *child;
	IXML_Element *parent;

	doc = ixmlDocument_createDocument();

	root=ixmlDocument_createElementNS(doc, "urn:schemas-upnp-org:device-1-0","root");
	ixmlElement_setAttribute(root, "xmlns", "urn:schemas-upnp-org:device-1-0");
	ixmlNode_appendChild((IXML_Node *)doc,(IXML_Node *)root);
	child=gen_specversion(doc,1,0);
	ixmlNode_appendChild((IXML_Node *)root,(IXML_Node *)child);
	parent=ixmlDocument_createElement(doc, "device");
	ixmlNode_appendChild((IXML_Node *)root,(IXML_Node *)parent);
	add_value_element(doc,parent,"deviceType",(char *)device_def->device_type);
	add_value_element(doc,parent,"presentationURL",(char *)device_def->presentation_url);
	add_value_element(doc,parent,"friendlyName",(char *)device_def->friendly_name);
	add_value_element(doc,parent,"manufacturer",(char *)device_def->manufacturer);
	add_value_element(doc,parent,"manufacturerURL",(char *)device_def->manufacturer_url);
	add_value_element(doc,parent,"modelDescription",(char *)device_def->model_description);
	add_value_element(doc,parent,"modelName",(char *)device_def->model_name);
	add_value_element(doc,parent,"modelURL",(char *)device_def->model_url);
	add_value_element(doc,parent,"UDN",(char *)device_def->udn);
	//add_value_element(doc,parent,"modelNumber",(char *)device_def->model_number);
	//add_value_element(doc,parent,"serialNumber",(char *)device_def->serial_number);
	//add_value_element(doc,parent,"UPC",(char *)device_def->upc);
	//if (device_def->icons) {
	//	child=gen_desc_iconlist(doc,device_def->icons);
	//	ixmlNode_appendChild((IXML_Node *)parent,(IXML_Node *)child);
	//}
	child=gen_desc_servicelist(device_def, doc);
	ixmlNode_appendChild((IXML_Node *)parent,(IXML_Node *)child);

	return doc;
}


struct service *find_service(struct device *device_def,
                             char *service_name)
{
	struct service *event_service;
	int serviceNum = 0;
	while (event_service =
	       device_def->services[serviceNum], event_service != NULL) {
	       UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
			"find_service : service %d name = %s\n", serviceNum, event_service->service_name);
		if (strcmp(event_service->service_name, service_name) == 0)
			return event_service;
		serviceNum++;
	}
	return NULL;
}

struct action *find_action(struct service *event_service,
				  char *action_name)
{
	struct action *event_action;
	int actionNum = 0;
	if (event_service == NULL)
		return NULL;
	while (event_action =
	       &(event_service->actions[actionNum]),
	       event_action->action_name != NULL) {
	       UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
			"find_action : action %d name = %s\n", actionNum, event_action->action_name);
		if (strcmp(event_action->action_name, action_name) == 0)
			return event_action;
		actionNum++;
	}
	return NULL;
}
#if 0
char *upnp_get_scpd(struct service *srv)
{
	char *result = NULL;
	IXML_Document *doc;

	doc = generate_scpd(srv);
	if (doc != NULL)
	{
       		result = ixmlDocumenttoString(doc);
		ixmlDocument_free(doc);
	}
	UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
		"upnp_get_scpd result len = %d\n", strlen(result));
	return result;
}
#endif
	extern int tls_fls_fast_write_init(void);
	extern int tls_fls_fast_write_destroy(void);
	extern int tls_fls_fast_write(u32 addr, u8 *buf, u32 length);
static void md5_update(struct MD5Context *ctx, unsigned char const *buf, int *total_len, u8 write_flag, u32 location)
{
	int len = strlen((char *)buf);
	if(write_flag)
	{
		if(tls_fls_fast_write(location + *total_len + 20, (u8*)buf, len))
		{
			UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
				"tls_fls_write error!!!!!!!!!!!!!!\n");
		}
#if 0
		else
		{
			char * readbuf;
			readbuf = tls_mem_alloc(len + 1);
			if(readbuf)
			{
				memset(readbuf, 0, len + 1);
				tls_fls_read(location + *total_len + 20, readbuf, len);
				if(memcmp(readbuf, buf, len))
				{
					printf("location=%x, len=%d\n", location + *total_len + 20, len);
					printf("writebuf=%s\n", buf);
					printf("readbuf=%s\n", readbuf);
				}
				tls_mem_free(readbuf);
			}
		}
#endif
	}
	else
		MD5Update(ctx, buf, len);
	*total_len += len;
}
static int write_scpd_file(u8 write_flag, struct service *srv, u8 *md5)
{
	int result = 0, i, location = srv->scpd_location;
	IXML_Document *doc;
	IXML_Element *child;
	char *buf;
	struct MD5Context ctx;
	
	if(write_flag)
	{
		tls_fls_fast_write_init();
		tls_fls_write(srv->scpd_location, md5, 16);
	}
	else
		MD5Init(&ctx);
	doc = ixmlDocument_createDocument();
	md5_update(&ctx, "<?xml version=\"1.0\"?>\r\n<scpd xmlns=\"urn:schemas-upnp-org:service-1-0\">\r\n", &result, write_flag, location);
	
	child=gen_specversion(doc,1,0);
	buf = ixmlNodetoString((IXML_Node *)child);
	md5_update(&ctx, (unsigned char*)buf, &result, write_flag, location);
	ixmlNode_free((IXML_Node *)child);
	tls_mem_free(buf);
	md5_update(&ctx, "<actionList>\r\n", &result, write_flag, location);
	for(i=0; i<srv->command_count; i++) {
		struct action *act;
		struct argument **arglist;
		const char **varnames;
		act=&(srv->actions[i]);
		arglist=srv->action_arguments[i];
		varnames=srv->variable_names;
		if (act) {
			child=gen_scpd_action(doc, act, arglist, varnames);
			buf = ixmlNodetoString((IXML_Node *)child);
			md5_update(&ctx, (unsigned char*)buf, &result, write_flag, location);
			ixmlNode_free((IXML_Node *)child);
			tls_mem_free(buf);
		}
	}
	md5_update(&ctx, "</actionList>\r\n<serviceStateTable>\r\n", &result, write_flag, location);
	for(i=0; i<srv->variable_count; i++) {
		struct var_meta *meta = &(srv->variable_meta[i]);
		const char *name = srv->variable_names[i];
		child=gen_scpd_statevar(doc,name,meta);
		buf = ixmlNodetoString((IXML_Node *)child);
		md5_update(&ctx, (unsigned char*)buf, &result, write_flag, location);
		ixmlNode_free((IXML_Node *)child);
		tls_mem_free(buf);
	}
	md5_update(&ctx, "</serviceStateTable>\r\n</scpd>", &result, write_flag, location);
	if(write_flag)
	{
		tls_fls_write(srv->scpd_location + 16, (u8 *)&result, 4);
		tls_fls_fast_write_destroy();
	}
	else
		MD5Final(md5, &ctx);
	return result;
}

int upnp_write_scpd_file(struct service *srv)
{
	u8 md5[16], md5_fls[16];
	u8 write_flg = 0;
	u32 length;
	length = write_scpd_file(write_flg, srv, md5);
	tls_fls_read(srv->scpd_location, md5_fls, 16);
	if(memcmp(md5, md5_fls, 16) == 0)
	{
		UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
			"file %s no change\n", srv->scpd_url);
		return length;
	}
	write_flg = 1;
	length = write_scpd_file(write_flg, srv, md5);
	return length;
}
#if 0
static int read_scpd_file(char *src, int startPos, int pos, char *dest, size_t destlen)
{
	int ret, offset;
	int src_len = strlen(src);
	
	if(pos >= startPos + src_len || pos < startPos)
		return 0;
	offset = pos - startPos;
	ret = src_len - offset;
	ret = destlen > ret ? ret : destlen;
	memcpy(dest, src + offset, ret);
	return ret;
}
#endif

int upnp_read_scpd_file(struct service *srv, int pos, char *dest, size_t destlen)
{
	if(tls_fls_read(srv->scpd_location + 20 + pos, (u8 *)dest, destlen) == TLS_FLS_STATUS_OK)
		return destlen;
	else
	{
		printf("upnp_read_scpd_fileerror\n");
		return 0;
	}
#if 0
	int readlen = 0, ret = 0;
	int result = 0, i;
	IXML_Document *doc;
	IXML_Element *child;
	char *buf;
	char *dest_off = dest;
	u8 free_child = 0;

	doc = ixmlDocument_createDocument();
	if((readlen = read_scpd_file("<?xml version=\"1.0\"?>\r\n<scpd xmlns=\"urn:schemas-upnp-org:service-1-0\">\r\n", result, pos, dest_off, destlen)) > 0)
	{
		dest_off += readlen;
		ret += readlen;
		pos += readlen;
		destlen -= readlen;
		if(destlen == 0)
			goto out;
	}
	result += 72;//"<?xml version=\"1.0\"?>\r\n<scpd xmlns=\"urn:schemas-upnp-org:service-1-0\">\r\n"

	child=gen_specversion(doc,1,0);
	buf = ixmlNodetoString(child);
	if((readlen = read_scpd_file(buf, result, pos, dest_off, destlen)) > 0)
	{
		dest_off += readlen;
		ret += readlen;
		pos += readlen;
		destlen -= readlen;
		if(destlen == 0)
		{
			free_child = 1;
			goto out;
		}
	}
	result += strlen(buf);
	ixmlNode_free(child);
	tls_mem_free(buf);
	if((readlen = read_scpd_file("<actionList>\r\n", result, pos, dest_off, destlen)) > 0)
	{
		dest_off += readlen;
		ret += readlen;
		pos += readlen;
		destlen -= readlen;
		if(destlen == 0)
			goto out;
	}
	result += 14;//<actionList>\r\n
	for(i=0; i<srv->command_count; i++) {
		struct action *act;
		struct argument **arglist;
		const char **varnames;
		act=&(srv->actions[i]);
		arglist=srv->action_arguments[i];
		varnames=srv->variable_names;
		if (act) {
			child=gen_scpd_action(doc, act, arglist, varnames);
			buf = ixmlNodetoString(child);
			if((readlen = read_scpd_file(buf, result, pos, dest_off, destlen)) > 0)
			{
				dest_off += readlen;
				ret += readlen;
				pos += readlen;
				destlen -= readlen;
				if(destlen == 0)
				{
					free_child = 1;
					goto out;
				}
			}
			result += strlen(buf);
			ixmlNode_free(child);
			tls_mem_free(buf);
		}
	}
	if((readlen = read_scpd_file("</actionList>\r\n<serviceStateTable>\r\n", result, pos, dest_off, destlen)) > 0)
	{
		dest_off += readlen;
		ret += readlen;
		pos += readlen;
		destlen -= readlen;
		if(destlen == 0)
			goto out;
	}
	result += 36;//</actionList>\r\n<serviceStateTable>\r\n
	for(i=0; i<srv->variable_count; i++) {
		struct var_meta *meta = &(srv->variable_meta[i]);
		const char *name = srv->variable_names[i];
		child=gen_scpd_statevar(doc,name,meta);
		buf = ixmlNodetoString(child);
		if((readlen = read_scpd_file(buf, result, pos, dest_off, destlen)) > 0)
		{
			dest_off += readlen;
			ret += readlen;
			pos += readlen;
			destlen -= readlen;
			if(destlen == 0)
			{
				free_child = 1;
				goto out;
			}
		}
		result += strlen(buf);
		ixmlNode_free(child);
		tls_mem_free(buf);
	}
	if((readlen = read_scpd_file("</serviceStateTable>\r\n</scpd>", result, pos, dest_off, destlen)) > 0)
	{
		ret += readlen;
		goto out;
	}
	result += 29;//</serviceStateTable>\r\n</scpd>
out:	
	if(free_child)
	{
		ixmlNode_free(child);
		tls_mem_free(buf);
	}
	ixmlDocument_free(doc);
	return ret;
#endif
}

char *upnp_get_device_desc(struct device *device_def)
{
	char *result = NULL;
	IXML_Document *doc;

	doc = generate_desc(device_def);

	if (doc != NULL)
	{
       		result = ixmlDocumenttoString(doc);
		ixmlDocument_free(doc);
	}
	return result;
}

