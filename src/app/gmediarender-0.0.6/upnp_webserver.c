/* webserver.c - Web server callback routines
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

#include <stdio.h>
#include <stdlib.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <unistd.h>
//#include <errno.h>
//#include <error.h>

#include <upnp.h>
#include <ithread.h>

#include "logging.h"
#include "upnp_webserver.h"
#include "UpnpStdInt.h"
#include "upnpdebug.h"

#define PATH_MAX 512

typedef struct {
	off_t pos;
	const char *contents;
	size_t len;
	struct service *srv;
} WebServerFile;

struct virtual_file;

static struct virtual_file {
	const char *virtual_fname;
	const char *contents;
	const char *content_type;
	size_t len;
	struct service *srv;
	struct virtual_file *next;
} *virtual_files = NULL;

int webserver_register_buf(struct service *srv, const char *path, size_t len, const char *content_type)
{
	int result = -1;
	struct virtual_file *entry;

	ENTER();

	entry = tls_mem_alloc(sizeof(struct virtual_file));
	if (entry == NULL) {
		goto out;
	}
	entry->len = len;
	entry->srv = srv;
	entry->virtual_fname = path;
	entry->content_type = content_type;
	entry->next = virtual_files;
	virtual_files = entry;
	result = 0;

out:
	LEAVE();
	return result;
}

#if 0
int webserver_register_file(const char *path, const char *content_type)
{
	char local_fname[PATH_MAX];
	struct stat buf;
	struct virtual_file *entry;
	int rc;
	int result = -1;

	ENTER();

	snprintf(local_fname, PATH_MAX, "%s%s", PKG_DATADIR,
	         strrchr(path, '/'));

	rc = stat(local_fname, &buf);
	if (rc) {
		error(0, errno, "Could not stat '%s'", local_fname);
		goto out;
	}

	entry = tls_mem_alloc(sizeof(struct virtual_file));
	if (entry == NULL) {
		goto out;
	}
	if (buf.st_size) {
		char *cbuf;
		FILE *in;
		in = fopen(local_fname, "r");
		if (in == NULL) {
			tls_mem_free(entry);
			goto out;
		}
		cbuf = tls_mem_alloc(buf.st_size);
		if (cbuf == NULL) {
			tls_mem_free(entry);
			goto out;
		}
		fread(cbuf, buf.st_size, 1, in);
		fclose(in);
		entry->len = buf.st_size;
		entry->contents = cbuf;

	} else {
		entry->len = 0;
		entry->contents = NULL;
	}
	entry->virtual_fname = path;
	entry->content_type = content_type;
	entry->next = virtual_files;
	virtual_files = entry;
	result = 0;
out:
	LEAVE();
	return result;
}
#endif

static int webserver_get_info(const char *filename, struct File_Info *info)
{
	int result = -1;
	
#ifdef DEBUG
	int n = 0;
#endif
	struct virtual_file *virtfile = virtual_files;

	ENTER();

	//fprintf(stderr, "%s:(filename='%s',info=%p)\n", __FUNCTION__,
	//	filename, info);

	while (virtfile != NULL) {
		UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
			"webserver_get_info : virtual file %d name = %s\n", n++, virtfile->virtual_fname);
		if (strcmp(filename, virtfile->virtual_fname) == 0) {
			info->file_length = virtfile->len;
			info->last_modified = 0;
			info->is_directory = 0;
			info->is_readable = 1;
			info->content_type =
			    ixmlCloneDOMString(virtfile->content_type);
			result = 0;
			goto out;
		}
		virtfile = virtfile->next;
	}
       UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
		"%s Not found\n", filename);
out:
	LEAVE();
	return result;
}

static UpnpWebFileHandle
webserver_open(const char *filename, enum UpnpOpenFileMode mode)
{
	struct virtual_file *virtfile = virtual_files;
	WebServerFile *file = NULL;

	ENTER();
	if (mode != UPNP_READ) {
		//fprintf(stderr,
		//	"%s: ignoring request to open file for writing\n",
		//	filename);
		goto out;
	}

	while (virtfile != NULL) {
		if (strcmp(filename, virtfile->virtual_fname) == 0) {
			file = tls_mem_alloc(sizeof(WebServerFile));
			if(file == NULL)
				return NULL;
			memset(file, 0, sizeof(WebServerFile));
			file->pos = 0;
			file->len = virtfile->len;
			file->contents = virtfile->contents;
			file->srv = virtfile->srv;
			goto out;
		}
		virtfile = virtfile->next;
	}

out:
	LEAVE();
	return file;
}

static inline int minimum(int a, int b)
{
	return (a<b)?a:b;
}

static int webserver_read(UpnpWebFileHandle fh, char *buf, size_t buflen)
{
	WebServerFile *file = (WebServerFile *) fh;
	ssize_t len = -1;

	ENTER();

	len = minimum(buflen, file->len - file->pos);
	if(file->srv)
	{
		len = upnp_read_scpd_file(file->srv, file->pos, buf, buflen);
		if(len)
			UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
				"buf=%s, len=%d\n",buf,len);
	}
	else
		memcpy(buf, file->contents + file->pos, len);

	if (len < 0) {
//		error(0, errno, "%s failed", __FUNCTION__);
	} else {
		file->pos += len;
	}
	UpnpPrintf( UPNP_INFO, API, __FILE__, __LINE__,
		"webserver_read pos=%d, buflen=%d\n", file->pos, buflen);
	LEAVE();
	return len;
}

static int webserver_write(UpnpWebFileHandle fh, char *buf, size_t buflen)
{
	ENTER();
	LEAVE();
	return -1;
}

static int webserver_seek(UpnpWebFileHandle fh, off_t offset, int origin)
{
	WebServerFile *file = (WebServerFile *) fh;
	off_t newpos = -1;
	int result = -1;
	
	ENTER();

	switch (origin) {
	case SEEK_SET:
		newpos = offset;
		break;
	case SEEK_CUR:
		newpos = file->pos + offset;
		break;
	case SEEK_END:
		newpos = file->len + offset;
		break;
	}

	if (newpos < 0 || newpos > file->len) {
//		error(0, errno, "%s seek failed", __FUNCTION__);
		goto out;
	}

	file->pos = newpos;
	result = 0;
out:
	LEAVE();
	return result;
}

static int webserver_close(UpnpWebFileHandle fh)
{
	WebServerFile *file = (WebServerFile *) fh;

	ENTER();

	tls_mem_free(file);

	LEAVE();
	return 0;
}

struct UpnpVirtualDirCallbacks virtual_dir_callbacks = {
	webserver_get_info,
	webserver_open,
	webserver_read,
	webserver_write,
	webserver_seek,
	webserver_close
};
