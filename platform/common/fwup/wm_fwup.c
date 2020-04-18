/***************************************************************************** 
* 
* File Name : wm_fwup.c
* 
* Description: firmware update Module 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-16
*****************************************************************************/ 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "wm_mem.h"
#include "list.h"
#include "wm_debug.h"
#include "wm_internal_flash.h"
#include "wm_flash.h"
#include "wm_crypto_hard.h"

#include "utils.h"
#include "wm_fwup.h"
#include "wm_watchdog.h"
#include "wm_wifi.h"
#include "wm_flash_map.h"
#include "wm_wl_task.h"
#include "wm_params.h"
#include "wm_param.h"

#define FWUP_MSG_QUEUE_SIZE      (4)

#define FWUP_TASK_STK_SIZE      (256)

#define FWUP_MSG_START_ENGINEER      (1)

static struct tls_fwup *fwup = NULL;
static tls_os_queue_t *fwup_msg_queue = NULL;

static u32 fwup_task_stk[FWUP_TASK_STK_SIZE];

static u8 oneshotback = 0;
static u8 *fwupwritebuffer = NULL;

T_BOOTER imgheader[2];
extern u32 flashtotalsize;
static void fwup_update_autoflag(void)
{
    u8 auto_reconnect = 0xff;

    tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_GET, &auto_reconnect);
    if(auto_reconnect == WIFI_AUTO_CNT_TMP_OFF)
    {
    	auto_reconnect = WIFI_AUTO_CNT_ON;
    	tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_SET, &auto_reconnect);
    }
    return;
}

int tls_fwup_img_header_check(T_BOOTER *img_param)
{
	psCrcContext_t	crcContext;
	u32 value = 0;
	int i = 0;
	u32 runaddr = 0;
	u32 updaddr = 0;

	if (img_param->magic_no != SIGNATURE_WORD)
	{
		return FALSE;	
	}

	if ((IMG_TYPE_OLD_PLAIN != img_param->img_type) && (IMG_TYPE_NEW_PLAIN != img_param->img_type))
	{
		return FALSE;
	}

	tls_crypto_crc_init(&crcContext, 0xFFFFFFFF, CRYPTO_CRC_TYPE_32, 3);
	for (i = 0; i <  (sizeof(T_BOOTER)-4)/4; i++)
	{
		value = *(((int *)img_param)+i);
		tls_crypto_crc_update(&crcContext, (unsigned char *)&value, 4);
	}
	value = 0;
	tls_crypto_crc_final(&crcContext, &value);

	runaddr = img_param->run_img_addr|FLASH_BASE_ADDR;
	if ((img_param->hd_checksum == value) && (runaddr < FLASH_1M_END_ADDR))
	{  
		/*forbid 1M_Plain and 2M_PLAIN update*/
		tls_fls_read(CODE_RUN_HEADER_ADDR, (unsigned char *)&imgheader[0], sizeof(T_BOOTER));
		if (imgheader[0].img_type != img_param->img_type)
		{
			return FALSE;
		}

		/*run addr must be page-aligned in first 1M flash */
		if ((runaddr % INSIDE_FLS_PAGE_SIZE)
			|| (0 == img_param->run_img_len)
			|| (runaddr + img_param->run_img_len >= FLASH_1M_END_ADDR)
			|| (runaddr < CODE_RUN_START_ADDR))
		{
			return FALSE;
		}

		/*can not upd over flash size minus system parameter area*/
		value = runaddr + img_param->run_img_len;
		if (value < imgheader[0].run_img_addr + imgheader[0].run_img_len)
		{
			value = (imgheader[0].run_img_addr|FLASH_BASE_ADDR) + imgheader[0].run_img_len;
		}

		value = value%INSIDE_FLS_BLOCK_SIZE ? (value/INSIDE_FLS_BLOCK_SIZE)*INSIDE_FLS_BLOCK_SIZE + INSIDE_FLS_BLOCK_SIZE : value;
		updaddr = img_param->upd_img_addr|FLASH_BASE_ADDR;
		/*upd address can not overlap run addr & must be 64K aligned*/
		if ((updaddr < value) 							
			|| (updaddr%INSIDE_FLS_BLOCK_SIZE) 			
			|| (0 == img_param->upd_img_len))
		{
			return FALSE;
		}

		/*over flash capacity decrease one block size used as sys param area*/
		if ((updaddr + img_param->upd_img_len) > ((flashtotalsize - INSIDE_FLS_BLOCK_SIZE)|FLASH_BASE_ADDR)) 
		{
			return FALSE;
		}

		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

static void tls_fwup_img_update_header(T_BOOTER* img_param)
{
	unsigned char current_img;	
	psCrcContext_t	crcContext;
	
	tls_fls_read(CODE_RUN_HEADER_ADDR, (unsigned char *)&imgheader[0], sizeof(T_BOOTER));
	tls_fls_read(CODE_UPD_HEADER_ADDR, (unsigned char *)&imgheader[1], sizeof(T_BOOTER));

	//将两个upd_no中较大的那个值取出来，再将其加1后赋值给 CODE_UPD_HEADER_ADDR 处的header；
	if (tls_fwup_img_header_check(&imgheader[1]))
	{
		current_img = (imgheader[1].upd_no > imgheader[0].upd_no);
	}
	else
	{
		current_img = 0;
	}
	img_param->upd_no = imgheader[current_img].upd_no + 1;
	
	tls_crypto_crc_init(&crcContext, 0xFFFFFFFF, CRYPTO_CRC_TYPE_32, 3);
	tls_crypto_crc_update(&crcContext, (unsigned char *)img_param, sizeof(T_BOOTER)-4);
	tls_crypto_crc_final(&crcContext, &img_param->hd_checksum);
	tls_fls_write(CODE_UPD_HEADER_ADDR,  (unsigned char *)img_param,  sizeof(T_BOOTER));
}

static void fwup_scheduler(void *data)
{
	u8 *buffer = NULL;
	int err;
	u32 msg;
	u32 len;	
	u32 image_checksum = 0;
	u32 org_checksum = 0;
	struct tls_fwup_request *request;
	struct tls_fwup_request *temp;
	T_BOOTER booter;
	u32 currentlen = 0;
	u32 tmplen = 0;
	bool isacrossflash = FALSE;

	while (1) 
	{
		err = tls_os_queue_receive(fwup_msg_queue, (void **)&msg, 0, 0);
        		tls_watchdog_clr();
		if(err != TLS_OS_SUCCESS) 
		{
			continue;
		}
		switch(msg) 
		{
			case FWUP_MSG_START_ENGINEER:
				if(dl_list_empty(&fwup->wait_list) == 0) 
				{
					fwup->current_state |= TLS_FWUP_STATE_BUSY;
				}
				dl_list_for_each_safe(request, temp, &fwup->wait_list, struct tls_fwup_request, list) 
				{
					request->status = TLS_FWUP_REQ_STATUS_BUSY;
					if(fwup->current_state & TLS_FWUP_STATE_ERROR) 
					{
						TLS_DBGPRT_WARNING("some error happened during firmware update, so discard all the request in the waiting queue!\n");
						if(fwup->current_state & TLS_FWUP_STATE_ERROR_IO) 
						{
							request->status = TLS_FWUP_REQ_STATUS_FIO;
						}
						else if(fwup->current_state & TLS_FWUP_STATE_ERROR_SIGNATURE) 
						{
							request->status = TLS_FWUP_REQ_STATUS_FSIGNATURE;
						}
						else if(fwup->current_state & TLS_FWUP_STATE_ERROR_MEM) 
						{	
							request->status = TLS_FWUP_REQ_STATUS_FMEM;
						}
						else if(fwup->current_state & TLS_FWUP_STATE_ERROR_CRC) 
						{
							request->status = TLS_FWUP_REQ_STATUS_FCRC;
						}
						goto request_finish;
					} 
					else if(fwup->current_state & TLS_FWUP_STATE_COMPLETE) 
					{
						TLS_DBGPRT_WARNING("the firmware updating conpletes, so discard the request in the waiting queue!\n");
						request->status = TLS_FWUP_REQ_STATUS_FCOMPLETE;
						goto request_finish;
					}

					if(fwup->current_image_src <= TLS_FWUP_IMAGE_SRC_WEB)
					{
					    buffer = request->data;
						if(fwup->received_len < sizeof(T_BOOTER))
						{
							len = sizeof(T_BOOTER) - fwup->received_len;
							if(request->data_len < len)
							{
								len = request->data_len;
							}
							MEMCPY(&booter, buffer, sizeof(T_BOOTER));
							request->data_len -= len;
							buffer += len;
							fwup->received_len += len;
							if(fwup->received_len == sizeof(T_BOOTER))
							{
								
								if (!tls_fwup_img_header_check(&booter))
								{
									request->status = TLS_FWUP_REQ_STATUS_FIO;
									fwup->current_state |= TLS_FWUP_STATE_ERROR_IO;
									goto request_finish;
								}
							
								if ((IMG_TYPE_OLD_PLAIN == booter.img_type ) ||(IMG_TYPE_NEW_PLAIN == booter.img_type))
								{
									fwup->program_base = booter.upd_img_addr | FLASH_BASE_ADDR;
									fwup->total_len = booter.upd_img_len;
									org_checksum = booter.upd_checksum;
									isacrossflash = FALSE;
									currentlen = 0;
								}
								else 
								{
									request->status = TLS_FWUP_REQ_STATUS_FCRC;
									goto request_finish;
								}

								fwup->updated_len = 0;
							}
						}
						fwup->received_len += request->data_len;
					}
					if ((request->data_len > 0) && (fwupwritebuffer))
					{
						if((currentlen + request->data_len) < INSIDE_FLS_SECTOR_SIZE)
						{
							memcpy(fwupwritebuffer + currentlen, buffer, request->data_len);
							currentlen += request->data_len;
							fwup->updated_len += request->data_len;
						}
						else
						{
							if ((IMG_TYPE_OLD_PLAIN == booter.img_type) \
								&& (0x200000 == flashtotalsize)\
								&& (fwup->program_base < FLASH_1M_END_ADDR)\
								&& ((fwup->program_base + fwup->updated_len) >= (FLASH_1M_END_ADDR - INSIDE_FLS_BLOCK_SIZE)))
							{
								isacrossflash = TRUE;
								fwup->program_base = FLASH_1M_END_ADDR;
								fwup->program_offset = 0;
							}

							//TLS_DBGPRT_INFO("write the firmware image to the flash. %x\n\r", fwup->program_base + fwup->program_offset);							
							memcpy(fwupwritebuffer + currentlen, buffer, (INSIDE_FLS_SECTOR_SIZE - currentlen));
							tmplen = fwup->program_offset/INSIDE_FLS_SECTOR_SIZE * INSIDE_FLS_SECTOR_SIZE;
							err = tls_fls_write(fwup->program_base + tmplen, fwupwritebuffer,  INSIDE_FLS_SECTOR_SIZE);
							if(err != TLS_FLS_STATUS_OK) 
							{
								TLS_DBGPRT_ERR("failed to program flash!\n");
								request->status = TLS_FWUP_REQ_STATUS_FIO;
								fwup->current_state |= TLS_FWUP_STATE_ERROR_IO;
								goto request_finish;
							}

							memcpy(fwupwritebuffer, buffer + (INSIDE_FLS_SECTOR_SIZE - currentlen), (currentlen + request->data_len) - INSIDE_FLS_SECTOR_SIZE);
							fwup->program_offset += INSIDE_FLS_SECTOR_SIZE;
							fwup->updated_len += request->data_len;
							currentlen = (currentlen + request->data_len) - INSIDE_FLS_SECTOR_SIZE;
						}

						//TLS_DBGPRT_INFO("updated: %d bytes\n" , fwup->updated_len);
						if(fwup->updated_len >= fwup->total_len) 
						{
							u32 left = 0, offset = 0;							
							psCrcContext_t	crcContext;
							
							if (fwup->program_offset <= fwup->updated_len)
							{
								if ((IMG_TYPE_OLD_PLAIN == booter.img_type) \
									&& (0x200000 == flashtotalsize)\
									&& (fwup->program_base < FLASH_1M_END_ADDR)\
									&& ((fwup->program_base + fwup->updated_len) >= (FLASH_1M_END_ADDR - INSIDE_FLS_BLOCK_SIZE)))
								{
									isacrossflash = TRUE;									
									fwup->program_base = FLASH_1M_END_ADDR;
									fwup->program_offset = 0;
								}

								err = tls_fls_write(fwup->program_base + fwup->program_offset, fwupwritebuffer,	currentlen);
								if(err != TLS_FLS_STATUS_OK) 
								{
									TLS_DBGPRT_ERR("failed to program flash!\n");
									request->status = TLS_FWUP_REQ_STATUS_FIO;
									fwup->current_state |= TLS_FWUP_STATE_ERROR_IO;
									goto request_finish;
								}
							}


							offset = 0;
							fwup->program_base = booter.upd_img_addr | FLASH_BASE_ADDR;
							if (TRUE == isacrossflash)
							{
								left = (FLASH_1M_END_ADDR - INSIDE_FLS_BLOCK_SIZE) - fwup->program_base;
							}
							else
							{
								left = fwup->total_len;
							}

							tls_crypto_crc_init(&crcContext, 0xFFFFFFFF, CRYPTO_CRC_TYPE_32, 3);
							while (left > 0) 
							{
								len = left > INSIDE_FLS_SECTOR_SIZE ? INSIDE_FLS_SECTOR_SIZE : left;

								err = tls_fls_read(fwup->program_base + offset, fwupwritebuffer, len);
								if (err != TLS_FLS_STATUS_OK) 
								{
									request->status = TLS_FWUP_REQ_STATUS_FIO;
									fwup->current_state |= TLS_FWUP_STATE_ERROR_IO;
									goto request_finish;
								}
								tls_crypto_crc_update(&crcContext, fwupwritebuffer, len);
								offset += len;
								left -= len;
							}

							if (TRUE == isacrossflash)
							{
								left = fwup->total_len - offset;
								fwup->program_base = FLASH_1M_END_ADDR;
								offset = 0;
								while (left > 0) 
								{
									len = left > INSIDE_FLS_SECTOR_SIZE ? INSIDE_FLS_SECTOR_SIZE : left;

									err = tls_fls_read(fwup->program_base + offset, fwupwritebuffer, len);
									if (err != TLS_FLS_STATUS_OK) 
									{
										request->status = TLS_FWUP_REQ_STATUS_FIO;
										fwup->current_state |= TLS_FWUP_STATE_ERROR_IO;
										goto request_finish;
									}
									tls_crypto_crc_update(&crcContext, fwupwritebuffer, len);
									offset += len;
									left -= len;
								}	
							}
							tls_crypto_crc_final(&crcContext, &image_checksum);								

							if (org_checksum != image_checksum)			
							{
								TLS_DBGPRT_ERR("varify incorrect[0x%02x, but 0x%02x]\n", org_checksum, image_checksum);
								request->status = TLS_FWUP_REQ_STATUS_FCRC;
								fwup->current_state |= TLS_FWUP_STATE_ERROR_CRC;
								goto request_finish;
							}
							else  /*CRC MATCH and Update IMAGE HEADER PARAM*/
							{
								tls_fwup_img_update_header(&booter);
							}

							TLS_DBGPRT_INFO("update the firmware successfully!\n");
							fwup->current_state |= TLS_FWUP_STATE_COMPLETE;
							if (oneshotback == 1){
								tls_wifi_set_oneshot_flag(oneshotback);	// 恢复一键配置
							}
							
						}
					}
					request->status = TLS_FWUP_REQ_STATUS_SUCCESS;

request_finish:
					tls_os_sem_acquire(fwup->list_lock, 0);
					dl_list_del(&request->list);
					tls_os_sem_release(fwup->list_lock);
					if(dl_list_empty(&fwup->wait_list) == 1) 
					{
						fwup->current_state &= ~TLS_FWUP_STATE_BUSY;
					}
					if(request->complete) 
					{
						request->complete(request, request->arg);
					}
					if(fwup->updated_len >= (fwup->total_len))
					{
					    fwup_update_autoflag();
					    tls_sys_reset();
					}
				}
				break;

			default:
				break;
		}
	}
}

void fwup_request_complete(struct tls_fwup_request *request, void *arg)
{
	tls_os_sem_t *sem;

	if((request == NULL) || (arg == NULL)) 
	{
		return;
	}
	sem = (tls_os_sem_t *)arg;
	tls_os_sem_release(sem);
}

u32 tls_fwup_enter(enum tls_fwup_image_src image_src)
{
	u32 session_id = 0;
	u32 cpu_sr;

	tls_fwup_init();

	if (fwup == NULL) 
	{
		TLS_DBGPRT_INFO("fwup is null!\n");
		return 0;
	}
	if (fwup->busy == TRUE) 
	{
		TLS_DBGPRT_INFO("fwup is busy!\n");
		return 0;
	}

	cpu_sr = tls_os_set_critical();
	
	do 
	{
		session_id = rand();
	}while(session_id == 0);

	if (NULL == fwupwritebuffer)
	{
		fwupwritebuffer = tls_mem_alloc(INSIDE_FLS_SECTOR_SIZE);
		if (NULL == fwupwritebuffer)
		{
			tls_os_release_critical(cpu_sr);
			return 0;
		}	
	}
	
	fwup->current_state = 0;
	fwup->current_image_src = image_src;

	fwup->received_len = 0;
	fwup->total_len = 0;
	fwup->updated_len = 0;
	fwup->program_base = 0;
	fwup->program_offset = 0;
	fwup->received_number = -1;
		
	fwup->current_session_id = session_id;
	fwup->busy = TRUE;
	tls_os_release_critical(cpu_sr);	
	oneshotback = tls_wifi_get_oneshot_flag();
	if (oneshotback == 1){
		tls_wifi_set_oneshot_flag(0);	// 退出一键配置
	}

	tls_wifi_set_psflag(FALSE, 0);

	return session_id;
}

int tls_fwup_exit(u32 session_id)
{
	u32 cpu_sr;
	bool enable = FALSE;
	//tls_os_task_t fwtask;
	//tls_os_status_t osstatus = 0;
	
	if ((fwup == NULL) || (fwup->busy == FALSE)) 
	{
		return TLS_FWUP_STATUS_EPERM;
	}
	if (session_id != fwup->current_session_id) 
	{
		return TLS_FWUP_STATUS_ESESSIONID;
	}
	if (fwup->current_state & TLS_FWUP_STATE_BUSY) 
	{
		return TLS_FWUP_STATUS_EBUSY;
	}

	cpu_sr = tls_os_set_critical();
	if (fwupwritebuffer)
	{
		tls_mem_free(fwupwritebuffer);
		fwupwritebuffer = NULL;
	}
	fwup->current_state = 0;

	fwup->received_len = 0;
	fwup->total_len = 0;
	fwup->updated_len = 0;
	fwup->program_base = 0;
	fwup->program_offset = 0;
	fwup->received_number = -1;

	fwup->current_session_id = 0;
	fwup->busy = FALSE;	
	tls_os_release_critical(cpu_sr);

	if (oneshotback == 1){
		tls_wifi_set_oneshot_flag(oneshotback); // 恢复一键配置
	}
	tls_param_get(TLS_PARAM_ID_PSM, &enable, TRUE);	
	tls_wifi_set_psflag(enable, 0);

	return TLS_FWUP_STATUS_OK;
}

int tls_fwup_get_current_session_id(void)
{
	if (fwup){
		return fwup->current_session_id;
	}
	return 0;
}

int tls_fwup_set_update_numer(int number)
{
	if(1 == number - fwup->received_number)
	{
		fwup->received_number = number;
		return TLS_FWUP_STATUS_OK;
	}
	return TLS_FWUP_STATE_UNDEF;
}

int tls_fwup_get_current_update_numer(void)
{
	return fwup->received_number;
}

int tls_fwup_get_status(void)
{
	return fwup->busy;
}

int tls_fwup_set_crc_error(u32 session_id)
{
	if(fwup == NULL) 
	{
		return TLS_FWUP_STATUS_EPERM;
	}
	if(session_id != fwup->current_session_id) 
	{
		return TLS_FWUP_STATUS_ESESSIONID;
	}
	fwup->current_state |= TLS_FWUP_STATE_ERROR_CRC;

	return TLS_FWUP_STATUS_OK;
}

static int tls_fwup_request_async(u32 session_id, struct tls_fwup_request *request)
{
	u8 need_sched;
	
	if(fwup == NULL) 
	{
		return TLS_FWUP_STATUS_EPERM;
	}
	if(session_id != fwup->current_session_id) 
	{
		return TLS_FWUP_STATUS_ESESSIONID;
	}
	if((request == NULL) || (request->data == NULL) || (request->data_len == 0)) 
	{
		return TLS_FWUP_STATUS_EINVALID;
	}
	tls_os_sem_acquire(fwup->list_lock, 0);
	if(dl_list_empty(&fwup->wait_list)) 
	{
		need_sched = 1;
	}
	else
	{
		need_sched = 0;
	}
	request->status = TLS_FWUP_REQ_STATUS_IDLE;
	dl_list_add_tail(&fwup->wait_list, &request->list);
	tls_os_sem_release(fwup->list_lock);
	if(need_sched == 1) 
	{
		tls_os_queue_send(fwup_msg_queue, (void *)FWUP_MSG_START_ENGINEER, 0);
	}
	return TLS_FWUP_STATUS_OK;
}


int tls_fwup_request_sync(u32 session_id, u8 *data, u32 data_len)
{
	int err;
	tls_os_sem_t *sem;
	struct tls_fwup_request request;

	if(fwup == NULL) 
	{
		return TLS_FWUP_STATUS_EPERM;
	}
	if(session_id != fwup->current_session_id) 
	{
		return TLS_FWUP_STATUS_ESESSIONID;
	}
	if((data == NULL) || (data_len == 0)) 
	{
		return TLS_FWUP_STATUS_EINVALID;
	}

	err = tls_os_sem_create(&sem, 0);
	if(err != TLS_OS_SUCCESS) 
	{
		return TLS_FWUP_STATUS_EMEM;
	}
	request.data = data;
	request.data_len = data_len;
	request.complete = fwup_request_complete;
	request.arg = (void *)sem;

	tls_wifi_set_psflag(FALSE, 0);
	
	err = tls_fwup_request_async(session_id, &request);
	if(err == TLS_FWUP_STATUS_OK) 
	{
		tls_os_sem_acquire(sem, 0);
	}
	tls_os_sem_delete(sem);

	switch(request.status) 
	{
		case TLS_FWUP_REQ_STATUS_SUCCESS:
			err = TLS_FWUP_STATUS_OK;
			break;

		case TLS_FWUP_REQ_STATUS_FIO:
			err = TLS_FWUP_STATUS_EIO;
			break;

		case TLS_FWUP_REQ_STATUS_FSIGNATURE:
			err = TLS_FWUP_STATUS_ESIGNATURE;
			break;

		case TLS_FWUP_REQ_STATUS_FMEM:
			err = TLS_FWUP_STATUS_EMEM;
			break;

		case TLS_FWUP_REQ_STATUS_FCRC:
			err = TLS_FWUP_STATUS_ECRC;
			break;

		case TLS_FWUP_REQ_STATUS_FCOMPLETE:
			err = TLS_FWUP_STATUS_EIO;
			break;

		default:
			err = TLS_FWUP_STATUS_EUNDEF;
			break;
	}
	return err;
}

u16 tls_fwup_current_state(u32 session_id)
{
	if(fwup == NULL) 
	{
		return TLS_FWUP_STATE_UNDEF;
	}
	if(session_id != fwup->current_session_id) 
	{
		return TLS_FWUP_STATE_UNDEF;
	}
	return fwup->current_state;
}

int tls_fwup_reset(u32 session_id)
{
	u32 cpu_sr;
	
	if ((fwup == NULL) || (fwup->busy == FALSE)) {return TLS_FWUP_STATUS_EPERM;}
	if (session_id != fwup->current_session_id) {return TLS_FWUP_STATUS_ESESSIONID;}
	if (fwup->current_state & TLS_FWUP_STATE_BUSY) {return TLS_FWUP_STATUS_EBUSY;}

	cpu_sr = tls_os_set_critical();

	fwup->current_state = 0;

	fwup->received_len = 0;
	fwup->total_len = 0;
	fwup->updated_len = 0;
	fwup->program_base = 0;
	fwup->program_offset = 0;
	
	tls_os_release_critical(cpu_sr);
	
	return TLS_FWUP_STATUS_OK;
}

int tls_fwup_clear_error(u32 session_id)
{
	u32 cpu_sr;
	
	if ((fwup == NULL) || (fwup->busy == FALSE)) {return TLS_FWUP_STATUS_EPERM;}
	if (session_id != fwup->current_session_id) {return TLS_FWUP_STATUS_ESESSIONID;}
	if (fwup->current_state & TLS_FWUP_STATE_BUSY) {return TLS_FWUP_STATUS_EBUSY;}

	cpu_sr = tls_os_set_critical();

	fwup->current_state &= ~TLS_FWUP_STATE_ERROR;
	
	tls_os_release_critical(cpu_sr);

	return TLS_FWUP_STATUS_OK;
}

int tls_fwup_init(void)
{
	int err;

	if(fwup != NULL) 
	{
		TLS_DBGPRT_ERR("firmware update module has been installed!\n");
		return TLS_FWUP_STATUS_EBUSY;
	}

	fwup = tls_mem_alloc(sizeof(*fwup));
	if(fwup == NULL) 
	{
		TLS_DBGPRT_ERR("allocate @fwup fail!\n");
		return TLS_FWUP_STATUS_EMEM;
	}
	memset(fwup, 0, sizeof(*fwup));
	
	err = tls_os_sem_create(&fwup->list_lock, 1);
	if(err != TLS_OS_SUCCESS) 
	{
		TLS_DBGPRT_ERR("create semaphore @fwup->list_lock fail!\n");
		tls_mem_free(fwup);
		return TLS_FWUP_STATUS_EMEM;
	}

	dl_list_init(&fwup->wait_list);
	fwup->busy = FALSE;

	err = tls_os_queue_create(&fwup_msg_queue, FWUP_MSG_QUEUE_SIZE);
	if (err != TLS_OS_SUCCESS) 
	{
		TLS_DBGPRT_ERR("create message queue @fwup_msg_queue fail!\n");
		tls_os_sem_delete(fwup->list_lock);
		tls_mem_free(fwup);
		return TLS_FWUP_STATUS_EMEM;
	}

	err = tls_os_task_create(NULL, "fwup",
						fwup_scheduler,
						(void *)fwup,
						(void *)&fwup_task_stk[0],
						FWUP_TASK_STK_SIZE * sizeof(u32),
						TLS_FWUP_TASK_PRIO,
						0);
	if (err != TLS_OS_SUCCESS)
	{
		TLS_DBGPRT_ERR("create firmware update process task fail!\n");

		tls_os_queue_delete(fwup_msg_queue);
		tls_os_sem_delete(fwup->list_lock);
		tls_mem_free(fwup);
		return TLS_FWUP_STATUS_EMEM;
	}

	return TLS_FWUP_STATUS_OK;
}


/**Run-time image area size*/
unsigned int CODE_RUN_AREA_LEN = 0;

/**Area can be used by User in 1M position*/
unsigned int USER_ADDR_START = 0;
unsigned int TLS_FLASH_PARAM_DEFAULT = 0;
unsigned int USER_AREA_LEN = 0;
unsigned int USER_ADDR_END = 0;


/**Upgrade image header area & System parameter area */
unsigned int CODE_UPD_HEADER_ADDR = 0;
unsigned int TLS_FLASH_PARAM1_ADDR = 0;
unsigned int TLS_FLASH_PARAM2_ADDR = 0;
unsigned int TLS_FLASH_PARAM_RESTORE_ADDR = 0;

/**Upgrade image area*/
unsigned int CODE_UPD_START_ADDR = 0;
unsigned int CODE_UPD_AREA_LEN = 0;

/**Area can be used by User in 2M position*/
unsigned int EX_USER_ADDR_START = 0;
unsigned int EX_USER_AREA_LEN = 0;
unsigned int EX_USER_ADDR_END = 0;

unsigned int TLS_FLASH_END_ADDR = 0;

void tls_fls_layout_init(void)
{
	T_BOOTER tbooter;

	tls_fls_read(CODE_RUN_HEADER_ADDR, (u8 *)&tbooter, sizeof(tbooter));
	switch (flashtotalsize)
	{
		case 0x200000: /*2M*/
		{
			if (IMG_TYPE_OLD_PLAIN == tbooter.img_type)
			{
				//printf("2M use old layout\r\n");
				/**Run-time image area size*/
				CODE_RUN_AREA_LEN				=		(896*1024 - 256);
									
				/**Area can be used by User in 1M position*/
				USER_ADDR_START					=		(CODE_RUN_START_ADDR + CODE_RUN_AREA_LEN);
				TLS_FLASH_PARAM_DEFAULT  		=		(USER_ADDR_START);
				USER_AREA_LEN					=		(48*1024);
				USER_ADDR_END					=		(USER_ADDR_START + USER_AREA_LEN - 1);
									
									
				/**Upgrade image header area & System parameter area */
				CODE_UPD_HEADER_ADDR			=		(USER_ADDR_START + USER_AREA_LEN);
				TLS_FLASH_PARAM1_ADDR			=		(CODE_UPD_HEADER_ADDR + 0x1000);
				TLS_FLASH_PARAM2_ADDR			=		(TLS_FLASH_PARAM1_ADDR + 0x1000);
				TLS_FLASH_PARAM_RESTORE_ADDR	=		(TLS_FLASH_PARAM2_ADDR + 0x1000);
									
				/**Upgrade image area*/
				CODE_UPD_START_ADDR				=		(TLS_FLASH_PARAM_RESTORE_ADDR + 0x1000);
				CODE_UPD_AREA_LEN				=		(704*1024);
									
				/**Area can be used by User in 2M position*/
				EX_USER_ADDR_START				=		(CODE_UPD_START_ADDR + CODE_UPD_AREA_LEN);
				EX_USER_AREA_LEN				=		(320*1024);
				EX_USER_ADDR_END				=		(EX_USER_ADDR_START + EX_USER_AREA_LEN - 1);
									
				TLS_FLASH_END_ADDR				=		(EX_USER_ADDR_END);

			}
			else
			{
				//printf("2M use new layout\r\n");				
				/**Run-time image area size*/
				CODE_RUN_AREA_LEN				=	(960*1024 - 256);
				
				/**Upgrade image area*/
				CODE_UPD_START_ADDR				=	(CODE_RUN_START_ADDR + CODE_RUN_AREA_LEN);
				CODE_UPD_AREA_LEN				=	(768*1024);
				
				/**Area can be used by User*/
				USER_ADDR_START					=	(CODE_UPD_START_ADDR + CODE_UPD_AREA_LEN);
				TLS_FLASH_PARAM_DEFAULT  		=	(USER_ADDR_START);
				USER_AREA_LEN					=	(240*1024);
				USER_ADDR_END					=	(USER_ADDR_START + USER_AREA_LEN - 1);

				/**Area can be used by User in 2M position*/
				EX_USER_ADDR_START				=		0;
				EX_USER_AREA_LEN				=		0;
				EX_USER_ADDR_END				=		0;

				
				/**Upgrade image header area & System parameter area */
				CODE_UPD_HEADER_ADDR			=	(USER_ADDR_START + USER_AREA_LEN) ;
				TLS_FLASH_PARAM1_ADDR			=	(CODE_UPD_HEADER_ADDR + 0x1000);
				TLS_FLASH_PARAM2_ADDR			=	(TLS_FLASH_PARAM1_ADDR + 0x1000);
				TLS_FLASH_PARAM_RESTORE_ADDR	=	(TLS_FLASH_PARAM2_ADDR + 0x1000);
				TLS_FLASH_END_ADDR				=	(TLS_FLASH_PARAM_RESTORE_ADDR + 0x1000 -1);
			}
		}
		break;
		default:	/*1M*/
		{
			//printf("1M layout\r\n");			
			/**Run-time image area size*/
			CODE_RUN_AREA_LEN				=	(512*1024 - 256);
			
			/**Upgrade image area*/
			CODE_UPD_START_ADDR				=	(CODE_RUN_START_ADDR + CODE_RUN_AREA_LEN);
			CODE_UPD_AREA_LEN				=	(384*1024);
							
			/**Area can be used by User*/
			USER_ADDR_START					=	(CODE_UPD_START_ADDR + CODE_UPD_AREA_LEN);
			TLS_FLASH_PARAM_DEFAULT  		=	(USER_ADDR_START);
			USER_AREA_LEN					=	(48*1024);
			USER_ADDR_END					=	(USER_ADDR_START + USER_AREA_LEN - 1);

			/**Area can be used by User in 2M position*/
			EX_USER_ADDR_START				=		0;
			EX_USER_AREA_LEN				=		0;
			EX_USER_ADDR_END				=		0;
						
			/**Upgrade image header area & System parameter area */
			CODE_UPD_HEADER_ADDR			=	(USER_ADDR_START + USER_AREA_LEN);
			TLS_FLASH_PARAM1_ADDR			=	(CODE_UPD_HEADER_ADDR + 0x1000);
			TLS_FLASH_PARAM2_ADDR			=	(TLS_FLASH_PARAM1_ADDR + 0x1000);
			TLS_FLASH_PARAM_RESTORE_ADDR	=	(TLS_FLASH_PARAM2_ADDR + 0x1000);
			TLS_FLASH_END_ADDR				=	(TLS_FLASH_PARAM_RESTORE_ADDR + 0x1000 - 1);
			
		}
		break;
	}
}

