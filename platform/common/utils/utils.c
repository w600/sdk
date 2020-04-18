/**************************************************************************
 * File Name                   : utils.c
 * Author                      : 
 * Version                     : 1.0
 * Date                        : 
 * Description                 : 
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd. 
 * All rights reserved.
 *
 ***************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "wm_include.h"
#include "tls_common.h"
#include "wm_debug.h"
#include "wm_sockets.h"
#include "utils.h"


static const u8 crc8_tbl[256] = {
	0x00,0x91,0xe3,0x72,0x07,0x96,0xe4,0x75,
	0x0e,0x9f,0xed,0x7c,0x09,0x98,0xea,0x7b,
	0x1c,0x8d,0xff,0x6e,0x1b,0x8a,0xf8,0x69,
	0x12,0x83,0xf1,0x60,0x15,0x84,0xf6,0x67,
	0x38,0xa9,0xdb,0x4a,0x3f,0xae,0xdc,0x4d,
	0x36,0xa7,0xd5,0x44,0x31,0xa0,0xd2,0x43,
	0x24,0xb5,0xc7,0x56,0x23,0xb2,0xc0,0x51,
	0x2a,0xbb,0xc9,0x58,0x2d,0xbc,0xce,0x5f,
	0x70,0xe1,0x93,0x02,0x77,0xe6,0x94,0x05,
	0x7e,0xef,0x9d,0x0c,0x79,0xe8,0x9a,0x0b,
	0x6c,0xfd,0x8f,0x1e,0x6b,0xfa,0x88,0x19,
	0x62,0xf3,0x81,0x10,0x65,0xf4,0x86,0x17,
	0x48,0xd9,0xab,0x3a,0x4f,0xde,0xac,0x3d,
	0x46,0xd7,0xa5,0x34,0x41,0xd0,0xa2,0x33,
	0x54,0xc5,0xb7,0x26,0x53,0xc2,0xb0,0x21,
	0x5a,0xcb,0xb9,0x28,0x5d,0xcc,0xbe,0x2f,
	0xe0,0x71,0x03,0x92,0xe7,0x76,0x04,0x95,
	0xee,0x7f,0x0d,0x9c,0xe9,0x78,0x0a,0x9b,
	0xfc,0x6d,0x1f,0x8e,0xfb,0x6a,0x18,0x89,
	0xf2,0x63,0x11,0x80,0xf5,0x64,0x16,0x87,
	0xd8,0x49,0x3b,0xaa,0xdf,0x4e,0x3c,0xad,
	0xd6,0x47,0x35,0xa4,0xd1,0x40,0x32,0xa3,
	0xc4,0x55,0x27,0xb6,0xc3,0x52,0x20,0xb1,
	0xca,0x5b,0x29,0xb8,0xcd,0x5c,0x2e,0xbf,
	0x90,0x01,0x73,0xe2,0x97,0x06,0x74,0xe5,
	0x9e,0x0f,0x7d,0xec,0x99,0x08,0x7a,0xeb,
	0x8c,0x1d,0x6f,0xfe,0x8b,0x1a,0x68,0xf9,
	0x82,0x13,0x61,0xf0,0x85,0x14,0x66,0xf7,
	0xa8,0x39,0x4b,0xda,0xaf,0x3e,0x4c,0xdd,
	0xa6,0x37,0x45,0xd4,0xa1,0x30,0x42,0xd3,
	0xb4,0x25,0x57,0xc6,0xb3,0x22,0x50,0xc1,
	0xba,0x2b,0x59,0xc8,0xbd,0x2c,0x5e,0xcf
};

#ifndef isdigit
#define in_range(c, lo, up)  ((u8)c >= lo && (u8)c <= up)
#define isdigit(c)           in_range(c, '0', '9')
#endif
int chk_crc8(u8 *ptr, u32 len)
{
	u8 crc8;
	u8 data;

	crc8=0;
	while (len--!=0) {
		data = *ptr++;
		crc8 = crc8_tbl[crc8^data];
	}
	
	if(crc8==0x00) {return 0;}
	else {return -1;}
}

u8 get_crc8(u8 *ptr, u32 len)
{
	u8 crc8;
	u8 data;

	crc8=0;
	while (len--!=0) {
		data = *ptr++;
		crc8 = crc8_tbl[crc8^data];
	}
	
	return crc8;
}

u8 calculate_crc8(u8 crc8, u8 *ptr, u32 len)
{
	u8 data;

	while (len--!=0) {
		data = *ptr++;
		crc8 = crc8_tbl[crc8^data];
	}
	
	return crc8;
}

static u32 _cal_crc32(u32 crc_result, u8 data_8)
{
	u8 crc_out[32];
	u8 crc_buf[32];
	u8 in_data_buf[8];
	u32 i;
	u32 flag;

	flag = 0x01;

	for (i = 0; i < 32; i++) {
		crc_out[i] = 0;
	}
	

	for (i = 0; i < 8; i++) {
		in_data_buf[i] = (data_8 >> i) & flag;
	}

	for (i = 0; i < 32; i++) {
		crc_buf[i] = (unsigned char)(crc_result >> i) & flag;
	}

	crc_out[0]  = in_data_buf[1]^in_data_buf[7]^crc_buf[30]^crc_buf[24];
	crc_out[1]  = in_data_buf[0]^in_data_buf[1]^in_data_buf[6]^in_data_buf[7]^crc_buf[31]^crc_buf[30]^crc_buf[25]^crc_buf[24];
	crc_out[2]  = in_data_buf[0]^in_data_buf[1]^in_data_buf[5]^in_data_buf[6]^in_data_buf[7]^crc_buf[31]^crc_buf[30]^crc_buf[26]^crc_buf[25]^crc_buf[24];
	crc_out[3]  = in_data_buf[0]^in_data_buf[4]^in_data_buf[5]^in_data_buf[6]^crc_buf[31]^crc_buf[27]^crc_buf[26]^crc_buf[25];
	crc_out[4]  = in_data_buf[1]^in_data_buf[3]^in_data_buf[4]^in_data_buf[5]^in_data_buf[7]^crc_buf[30]^crc_buf[28]^crc_buf[27]^crc_buf[26]^crc_buf[24];
	crc_out[5]  = in_data_buf[0]^in_data_buf[1]^in_data_buf[2]^in_data_buf[3]^in_data_buf[4]^in_data_buf[6]^in_data_buf[7]^
                 crc_buf[31]^crc_buf[30]^crc_buf[29]^crc_buf[28]^crc_buf[27]^crc_buf[25]^crc_buf[24];
	crc_out[6]  = in_data_buf[0]^in_data_buf[1]^in_data_buf[2]^in_data_buf[3]^in_data_buf[5]^in_data_buf[6]^
                 crc_buf[31]^crc_buf[30]^crc_buf[29]^crc_buf[28]^crc_buf[26]^crc_buf[25];
	crc_out[7]  = in_data_buf[0]^in_data_buf[2]^in_data_buf[4]^in_data_buf[5]^in_data_buf[7]^crc_buf[31]^crc_buf[29]^crc_buf[27]^crc_buf[26]^crc_buf[24];
	crc_out[8]  = in_data_buf[3]^in_data_buf[4]^in_data_buf[6]^in_data_buf[7]^crc_buf[28]^crc_buf[27]^crc_buf[25]^crc_buf[24]^crc_buf[0];
	crc_out[9]  = in_data_buf[2]^in_data_buf[3]^in_data_buf[5]^in_data_buf[6]^crc_buf[29]^crc_buf[28]^crc_buf[26]^crc_buf[25]^crc_buf[1];
	crc_out[10] = in_data_buf[2]^in_data_buf[4]^in_data_buf[5]^in_data_buf[7]^crc_buf[29]^crc_buf[27]^crc_buf[26]^crc_buf[24]^crc_buf[2];
	crc_out[11] = in_data_buf[3]^in_data_buf[4]^in_data_buf[6]^in_data_buf[7]^crc_buf[28]^crc_buf[27]^crc_buf[25]^crc_buf[24]^crc_buf[3];
  
	crc_out[12] = in_data_buf[1]^in_data_buf[2]^in_data_buf[3]^in_data_buf[5]^in_data_buf[6]^in_data_buf[7]^
                 crc_buf[30]^crc_buf[29]^crc_buf[28]^crc_buf[26]^crc_buf[25]^crc_buf[24]^crc_buf[4];
	crc_out[13] = in_data_buf[0]^in_data_buf[1]^in_data_buf[2]^in_data_buf[4]^in_data_buf[5]^in_data_buf[6]^
                 crc_buf[31]^crc_buf[30]^crc_buf[29]^crc_buf[27]^crc_buf[26]^crc_buf[25]^crc_buf[5];
	crc_out[14] = in_data_buf[0]^in_data_buf[1]^in_data_buf[3]^in_data_buf[4]^in_data_buf[5]^crc_buf[31]^crc_buf[30]^crc_buf[28]^crc_buf[27]^crc_buf[26]^crc_buf[6];
	crc_out[15] = in_data_buf[0]^in_data_buf[2]^in_data_buf[3]^in_data_buf[4]^crc_buf[31]^crc_buf[29]^crc_buf[28]^crc_buf[27]^crc_buf[7];
	crc_out[16] = in_data_buf[2]^in_data_buf[3]^in_data_buf[7]^crc_buf[29]^crc_buf[28]^crc_buf[24]^crc_buf[8];
	crc_out[17] = in_data_buf[1]^in_data_buf[2]^in_data_buf[6]^crc_buf[30]^crc_buf[29]^crc_buf[25]^crc_buf[9];
	crc_out[18] = in_data_buf[0]^in_data_buf[1]^in_data_buf[5]^crc_buf[31]^crc_buf[30]^crc_buf[26]^crc_buf[10];
	crc_out[19] = in_data_buf[0]^in_data_buf[4]^crc_buf[31]^crc_buf[27]^crc_buf[11];
	crc_out[20] = in_data_buf[3]^crc_buf[28]^crc_buf[12];
	crc_out[21] = in_data_buf[2]^crc_buf[29]^crc_buf[13];
	crc_out[22] = in_data_buf[7]^crc_buf[24]^crc_buf[14];
	crc_out[23] = in_data_buf[1]^in_data_buf[6]^in_data_buf[7]^crc_buf[30]^crc_buf[25]^crc_buf[24]^crc_buf[15];
	crc_out[24] = in_data_buf[0]^in_data_buf[5]^in_data_buf[6]^crc_buf[31]^crc_buf[26]^crc_buf[25]^crc_buf[16];
	crc_out[25] = in_data_buf[4]^in_data_buf[5]^crc_buf[27]^crc_buf[26]^crc_buf[17];
	crc_out[26] = in_data_buf[1]^in_data_buf[3]^in_data_buf[4]^in_data_buf[7]^crc_buf[30]^crc_buf[28]^crc_buf[27]^crc_buf[24]^crc_buf[18];
	crc_out[27] = in_data_buf[0]^in_data_buf[2]^in_data_buf[3]^in_data_buf[6]^crc_buf[31]^crc_buf[29]^crc_buf[28]^crc_buf[25]^crc_buf[19];
	crc_out[28] = in_data_buf[1]^in_data_buf[2]^in_data_buf[5]^crc_buf[30]^crc_buf[29]^crc_buf[26]^crc_buf[20];
	crc_out[29] = in_data_buf[0]^in_data_buf[1]^in_data_buf[4]^crc_buf[31]^crc_buf[30]^crc_buf[27]^crc_buf[21];
	crc_out[30] = in_data_buf[0]^in_data_buf[3]^crc_buf[31]^crc_buf[28]^crc_buf[22];
	crc_out[31] = in_data_buf[2]^crc_buf[23]^crc_buf[29];
 
	crc_result = 0;
	for (i = 0; i < 32; i++) {
		if (crc_out[i]) {crc_result |= (1<<i);}
	}
	
	return crc_result;
}

u32 get_crc32(u8 *data, u32 data_size)
{
	u32 i;
	u32 val;
	int crc_result = 0xffffffff;
	
	for (i = 0; i < data_size; i++) {	
		crc_result = _cal_crc32(crc_result, data[i]);		
	}

	val = 0;
	for (i = 0; i < 32; i++) {
		if ((crc_result>>i) & 0x1) {val |= (1<<(31-i));}
	}

//	TLS_DBGPRT_INFO("calculate crc -0x%x .\n", ~val);
	return ~val;
}

u32 checksum(u32 *data, u32 length, u32 init)
{
	static long long sum = 0;
	u32 checksum;
	u32 i;

	/*
	    Calculate the checksum.
	*/
	if (!init) {sum = 0;}

	for (i = 0; i < length; i++) {sum+=*(data + i);}
	checksum = ~((u32)(sum>>32)+(u32)sum);

	return checksum;
}

int atodec(char ch)
{
	int dec = -1;
	
	if ((ch >= '0') && (ch <= '9')) {dec = ch - '0';}

	return dec;
}

int strtodec(int *dec, char *str)
{
	int i;
	int dd;
	int sign;

	i = -1;
	dd = 0;
	sign = 1;

	if (*str == '-') {
		str++;
		sign = -1;
	}

	while (*str) {
		i = atodec(*str++);
		if (i < 0) {return -1;}
		dd = dd*10 + i;
	}

	*dec = dd*sign;

	return ((i < 0) ? -1 : 0);
}

int atohex(char ch)
{
	int hex;

	hex = -1;
	
	if ((ch >= '0') && (ch <= '9')) {hex = ch - '0';}
	else if ((ch >= 'a') && (ch <= 'f')) {hex = ch - 'a' + 0xa;}
	else if ((ch >= 'A') && (ch <= 'F')) {hex = ch - 'A' + 0xa;}

	return hex;
}

int strtohex(u32 *hex, char *str)
{
	int n;
	int i;
	u32 dd;

	n = -1;
	i = 0;
	dd = 0;

	while(*str){
		n = atohex(*str++);
		if (n < 0) {return -1;}
		dd = (dd<<4) + n;
		if (++i > 8){return -1;}
	}

	*hex = dd;

	return (n<0?-1:0);
}

int strtohexarray(u8 array[], int cnt, char *str)
{
	int hex;
	u8 tmp;
	u8 *des;

	des = array;
	
	while (cnt-- > 0) {
		hex = atohex(*str++);
		if (hex < 0) {return -1;}
		else {tmp = (hex << 4) & 0xf0;}

		hex = atohex(*str++);
		if (hex < 0) {return -1;}
		else {tmp = tmp | (hex & 0x0f);}
		
		*des++ = (u8) tmp;
	}
	
	return ((*str==0) ? 0 : -1);
}

int strtoip(u32 *ipadr, char * str)
{
	int n;
	u32 i;
	u32 ip;
	char *head;
	char *tail;

	ip = 0;
	head = str;
	tail = str;
	
	for (i = 0; i < 3; ) {
		if (*tail == '.') {
			i++;
			*tail = 0;
			ip <<= 8;
			if (strtodec(&n, head) < 0) {return -1;}
			if ((n < 0) || (n > 255)) {return -1;}
			ip += n;
			*tail = '.';
			head = tail + 1;
		}		
		tail++;
	}

	if (i < 3) {return -1;}

	ip <<= 8;
	if (strtodec(&n, head) < 0) {return -1;}
	if ((n < 0) || (n > 255)) {return -1;}
	ip += n;

	*ipadr = ip;
	
	return ((ip == 0) ? -1 : 0);
}

void iptostr(u32 ip, char *str)
{
	sprintf(str, "%d.%d.%d.%d",
		((ip >> 24) & 0xff),((ip >> 16) & 0xff),\
		((ip >>  8) & 0xff), ((ip >>  0) & 0xff));
}


void mactostr(u8 mac[], char *str)
{
	sprintf(str, "%02x%02x%02x%02x%02x%02x",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}


int hex_to_digit(int c)
{
	if( '0' <= c && c <= '9' )
		return c - '0';
	if( 'A' <= c && c <= 'F' )
		return c - ('A' - 10);
	if( 'a' <= c && c <= 'f' )
		return c - ('a' - 10);
	return -1;
}

int digit_to_hex(int c)
{
	if( 0 <= c && c <= 9 )
		return c + '0';
	if( 0xA <= c && c <= 0xF )
		return c - 0xA + 'A' ;
	return -1; 
}

int hexstr_to_unit(char *buf, u32 *d)
{
    int i;
    int len = strlen(buf);
    int c;
    *d = 0;

    if (len > 8)
        return -1;
    for (i=0; i<len; i++) {
        c = hex_to_digit(buf[i]);
        if (c < 0)
            return -1;
        *d = (u8)c | (*d << 4);
    }
    return 0;
}
int string_to_uint(char *buf, u32 *d)
{
    int i;
    int len = strlen(buf);

    if (len > 11 || len == 0)
        return -1;
    for(i=0; i<len; i++) {
        if (!isdigit(buf[i]))
            return -1;
    }
    *d = atoi(buf);
    return 0;
}

int string_to_ipaddr(const char *buf, u8 *addr)
{
	int count = 0, rc = 0;
	int in[4];
	char c;

	rc = sscanf(buf, "%u.%u.%u.%u%c",
		    &in[0], &in[1], &in[2], &in[3], &c);
	if (rc != 4 && (rc != 5 || c != '\n'))
		return -1;
	for (count = 0; count < 4; count++) {
		if (in[count] > 255)
			return -1;
		addr[count] = in[count];
	}
	return 0;
}


char * strdup(const char *s)
{
	char * ret;
	int len;
	if(s == NULL)
		return NULL;
	len = strlen(s) + 1;
	ret = tls_mem_alloc(len);
	if(ret == NULL)
		return NULL;
	memset(ret, 0, len);
	memcpy(ret, s, len-1);
	return ret;
}

char * strndup(const char *s, size_t len)
{
	char * ret;
	if(s == NULL)
		return NULL;
	ret = tls_mem_alloc(len + 1);
	if(ret == NULL)
		return NULL;
	memset(ret, 0, len + 1);
	memcpy(ret, s, len);
	return ret;
}

int gettimeofday(struct timeval *tv, void *tz)
{
	int ret = 0;
	u32 current_tick; 

	current_tick = tls_os_get_time();//OSTimeGet();
	tv->tv_sec = (current_tick) / 100;
	tv->tv_usec = 10000 * (current_tick % 100);
	return ret;
}

int sendchar(int ch)
{
#if TLS_CONFIG_IOUART
    return tls_iouart_output_char(ch);
#else
    return tls_uart_output_char(ch);
#endif
}

//function:	将数据转换成字符串
//paramter:
//str	:	转换之后存在此buffer
//num	:	要转换的数据
//base	:	十进制，十六进制
//width	:	对齐宽度
//opflag :	操作符，bit定义如下

#define	P_ALIGN_BIT	(0x01<<0)	// bit=1 左对齐 bit=0右对齐
#define  P_FILL_BIT		(0x01<<1)	//bit = 1填充'0'，否则填充' '
#define  P_BIG_BIT		(0x01<<2)	//bit=1，大写，否则小写

int Int2Str(char *str,int num,char base,char width,int opflag) 
{   
	char temp; 
	int len = 0;
	signed char k = 0;
	char *str_bk;
	signed char k_bk;

	if(num <0) 
	{ 
		num = -num;   
		*str='-';
		str++;
		len++;  
	}
	if(0 == num)
	{
		*str = '0';
		str ++;
		k ++;
	}
	while(num) 
	{	
		temp= num%base; 
		if(temp > 9) // insert hexdecimal--ABCDEF-- 
		{  
			temp-=10;  
			if(opflag & P_BIG_BIT)
				*str = temp + 'A';  	
			else
				*str = temp + 'a';  
		} 
		else 
		{  
			*str = temp + '0'; 
		}
		num=num/base; 
		str++;
		k++; 
	}  

	if(opflag&P_ALIGN_BIT)	//左对齐
	{
		str_bk = str;
		k_bk = k;		//先备份指针和长度，倒序之后继续
		str --;
		k --;
		while(k>0) 
		{
			temp = *str; 
			*str = *(str-k); 
			*(str-k) = temp; 
			str--; 
			k-=2; 
		}  
		k = k_bk;
		str = str_bk;
	}	
 
	//不足宽度的用' '补齐
	while(width>k) 
	{  
		if(opflag&P_FILL_BIT)
		{
			*str++ ='0';
		}
		else
		{
			*str++ =' ';
		}
		k++; 
	}

	len=len+k; 
	*str-- = '\0'; 
	k--; 
 	if(0 == (opflag&P_ALIGN_BIT))	//右对齐
 	{
		//倒序 
		while(k>0) 
		{
			temp = *str; 
			*str = *(str-k); 
			*(str-k) = temp; 
			str--; 
			k-=2; 
		}  
 	} 
	return len; 
}  

static int IP2Str(unsigned char v4v6, unsigned int *inuint, char *outtxt)
{
    unsigned char i;
    unsigned char j = 0;
    unsigned char k;
    unsigned char h;
    unsigned char m;
    unsigned char l;
    unsigned char bit;

    if (4 == v4v6)
    {
        for(i = 0; i < 4; i++)
        {
            bit = (*inuint >> (8 * i)) & 0xff;
            h = bit / 100;
            if (h)
                outtxt[j++] = '0' + h;
            m = (bit % 100) / 10;
            if (m)
            {
                outtxt[j++] = '0' + m;
            }
            else
            {
                if (h)
                    outtxt[j++] = '0';
            }
            l = (bit % 100) % 10;
            outtxt[j++] = '0' + l;
            outtxt[j++] = '.';
        }
    }
    else
    {
        for (k = 0; k < 4; k++)
        {
            for(i = 0; i < 4; i++)
            {
                m = (*inuint >> (8 * i)) & 0xff;
                h = m >> 4;
                l = m & 0xf;
                if (h > 9)
                    outtxt[j++] = 'A' + h - 10;
                else 
                    outtxt[j++]= '0' + h;
                if (l > 9)
                    outtxt[j++] = 'A' + l - 10;
                else
                    outtxt[j++] = '0' + l;
                if (0 != (i % 2))
                    outtxt[j++] = ':';
            }
            inuint++;
        }
    }

    outtxt[j - 1] = 0;
    return j - 1;
}

static int Mac2Str(unsigned char *inchar, char *outtxt)
{
    unsigned char hbit,lbit;
    unsigned int i;

    for(i = 0; i < 6; i++)/* mac length */
    {
        hbit = (*(inchar + i) & 0xf0) >> 4;
        lbit = *(inchar + i ) & 0x0f;
        if (hbit > 9)
            outtxt[3 * i] = 'A' + hbit - 10;
        else 
            outtxt[3 * i]= '0' + hbit;
        if (lbit > 9)
            outtxt[3 * i + 1] = 'A' + lbit - 10;
        else
            outtxt[3 * i + 1] = '0' + lbit;
        outtxt[3 * i + 2] = '-';
    }

    outtxt[3 * (i - 1) + 2] = 0;

    return 3 * (i - 1) + 2;
}

int wm_vprintf(const char *fmt, va_list arg_ptr)
{
	unsigned char width=0; 	//保留宽度
	unsigned int len; 			//数据宽度
	char *fp = (char *)fmt;  
	//va_list arg_ptr; 
	char *pval;
	int opflag = 0;
	char store[40];
	char c;
	int i;
	char* str;
	
	//va_start(arg_ptr, fmt); //arg_ptr 指向第一个参数
	while (*fp !='\0') 
	{
		c = *fp++; 
		if (c != '%') 
		{
			sendchar(c);
		} 
		else 
		{ 
			width = 0;  //获取数据宽度
			opflag = 0;
			if('-' == *fp)
			{
				opflag |= P_ALIGN_BIT;//左对齐
				fp ++;
			}
			if('0' == *fp)	//前面补零
			{
				opflag |= P_FILL_BIT;	//补零
				fp ++;
			}

			while(*fp>='0'&&*fp<='9') 
			{  
				width = width * 10 + (*fp) - '0'; 
				fp++; 
			} 
			if('.' == *fp)	//浮点运算暂时没用，不处理
			{
				fp ++;
				while(*fp>='0'&&*fp<='9') 
				{  
					fp++; 
				}
			}

			while('l' == *fp || 'h' == *fp)
			{
				fp ++;
			}			
			
			switch (*fp) 
			{  
				case 'c': 
				case 'C': 
					c = (char)va_arg(arg_ptr, int);
			             sendchar(c);
					break; 
				case 'd': 
				case 'i':  
				case 'u':	
			              i = va_arg(arg_ptr, int);
			              str = store;
					Int2Str(store,i,10,width,opflag); 
      		                    while( *str != '\0') sendchar(*str++);
					break; 
				case 'x': 
				case 'X':  
			              i = va_arg(arg_ptr, int);
			              str = store;
					if('X' == *fp)
					{
						opflag |= P_BIG_BIT;
					}					 
					 Int2Str(store,i,16,width,opflag); 		   
			                while( *str != '\0') sendchar(*str++);
					break; 
				case 'o':
			             i = va_arg(arg_ptr, int);
			             str = store;
					Int2Str(store,i,8,width,opflag); 		   
       			      while( *str != '\0') sendchar(*str++);
					break;
				case 's': 
				case 'S':
					pval=va_arg(arg_ptr,char*);
					len = strlen(pval);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							sendchar(' ');
						}
					}
                                for(i=0;i < len;i++)
                                {
						sendchar(pval[i]);					
                                }
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							sendchar(' ');
						}
					}
					break; 
                case 'v':/* ip v4 address */
                    i = va_arg(arg_ptr, int);
                    len = IP2Str(4, (unsigned int *)&i, store);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							sendchar(' ');
						}
					}
                    str = store;
                    while( *str != '\0') sendchar(*str++);
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							sendchar(' ');
						}
					}
			        break;
			    case 'V':/* ip v6 address */
                    pval=va_arg(arg_ptr,char*);
                    len = IP2Str(6, (unsigned int *)pval, store);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							sendchar(' ');
						}
					}
                    str = store;
                    while( *str != '\0') sendchar(*str++);
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							sendchar(' ');
						}
					}
			        break;
				case 'M':/* mac address */
                    pval = va_arg(arg_ptr, char*);
                    len = Mac2Str((unsigned char *)pval, store);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							sendchar(' ');
						}
					}
                    str = store;
                    while( *str != '\0') sendchar(*str++);
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							sendchar(' ');
						}
					}
                    break;
				case '%':  
					sendchar('%');
					break; 
				default: 
					break; 
			}
			fp++; 
		} 
	}  
	//va_end(arg_ptr); 
	return 0; 
	
}

int wm_printf(const char *fmt,...) 
{
	va_list ap;

	va_start(ap, fmt);
	wm_vprintf(fmt,ap);
	va_end(ap);
	return 0;
}

int wm_vsnprintf(char *outstr, size_t size, const char *fmt, va_list arg_ptr)
{
	unsigned char width=0; 	//保留宽度
	unsigned int len; 			//数据宽度
	char *fp = (char *)fmt;  
	char *pval;
	int opflag = 0;
	char store[40];
	char c;
	int i;
	char* str;
	int ret = 0;

	while (*fp !='\0') 
	{
		c = *fp++; 
		if (c != '%') 
		{
			if ((ret + 1) >= size)
			    break;
			outstr[ret++] = c;
		} 
		else 
		{ 
			width = 0;  //获取数据宽度
			opflag = 0;
			if('-' == *fp)
			{
				opflag |= P_ALIGN_BIT;//左对齐
				fp ++;
			}
			if('0' == *fp)	//前面补零
			{
				opflag |= P_FILL_BIT;	//补零
				fp ++;
			}

			while(*fp>='0'&&*fp<='9') 
			{  
				width = width * 10 + (*fp) - '0'; 
				fp++; 
			} 
			if('.' == *fp)	//浮点运算暂时没用，不处理
			{
				fp ++;
				while(*fp>='0'&&*fp<='9') 
				{  
					fp++; 
				}
			}

			while('l' == *fp || 'h' == *fp)
			{
				fp ++;
			}			
			
			switch (*fp) 
			{  
				case 'c': 
				case 'C': 
					c = (char)va_arg(arg_ptr, int);
			        if ((ret + 1) >= size)
        			    break;
        			outstr[ret++] = c;
					break; 
				case 'd': 
				case 'i':  
				case 'u':	
                    i = va_arg(arg_ptr, int);
                    str = store;
                    Int2Str(store,i,10,width,opflag); 
                    while( *str != '\0')
                    {
                        if ((ret + 1) >= size)
        			        break;
        			    outstr[ret++] = *str++;
                    }
					break; 
				case 'x': 
				case 'X':  
                    i = va_arg(arg_ptr, int);
                    str = store;
                    if('X' == *fp)
                    {
                    opflag |= P_BIG_BIT;
                    }					 
                    Int2Str(store,i,16,width,opflag); 		   
                    while( *str != '\0')
                    {
                        if ((ret + 1) >= size)
        			        break;
        			    outstr[ret++] = *str++;
                    }
					break; 
				case 'o':
                    i = va_arg(arg_ptr, int);
                    str = store;
                    Int2Str(store,i,8,width,opflag); 		   
                    while( *str != '\0')
                    {
                        if ((ret + 1) >= size)
        			        break;
        			    outstr[ret++] = *str++;
                    }
					break;
				case 's': 
				case 'S':
					pval=va_arg(arg_ptr,char*);
					len = strlen(pval);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							if ((ret + 1) >= size)
        			            break;
        			        outstr[ret++] = ' ';
						}
					}
                                for(i=0;i < len;i++)
                                {
						            if ((ret + 1) >= size)
                			            break;
                			        outstr[ret++] = pval[i];
                                }
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							if ((ret + 1) >= size)
        			            break;
        			        outstr[ret++] = ' ';
						}
					}
					break; 
                case 'v':/* ip v4 address */
                    i = va_arg(arg_ptr, int);
                    len = IP2Str(4, (unsigned int *)&i, store);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							if ((ret + 1) >= size)
        			            break;
        			        outstr[ret++] = ' ';
						}
					}
                    str = store;
                    while( *str != '\0')
                    {
                        if ((ret + 1) >= size)
    			            break;
    			        outstr[ret++] = *str++;
                    }
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							if ((ret + 1) >= size)
        			            break;
        			        outstr[ret++] = ' ';
						}
					}
			        break;
			    case 'V':/* ip v6 address */
                    pval=va_arg(arg_ptr,char*);
                    len = IP2Str(6, (unsigned int *)pval, store);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							if ((ret + 1) >= size)
        			            break;
        			        outstr[ret++] = ' ';
						}
					}
                    str = store;
                    while( *str != '\0')
                    {
                        if ((ret + 1) >= size)
    			            break;
    			        outstr[ret++] = *str++;
                    }
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							if ((ret + 1) >= size)
        			            break;
        			        outstr[ret++] = ' ';
						}
					}
			        break;
				case 'M':/* mac address */
                    pval = va_arg(arg_ptr, char*);
                    len = Mac2Str((unsigned char *)pval, store);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							if ((ret + 1) >= size)
        			            break;
        			        outstr[ret++] = ' ';
						}
					}
                    str = store;
                    while( *str != '\0')
                    {
                        if ((ret + 1) >= size)
    			            break;
    			        outstr[ret++] = *str++;
                    }
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							if ((ret + 1) >= size)
        			            break;
        			        outstr[ret++] = ' ';
						}
					}
                    break;
				case '%':  
					if ((ret + 1) >= size)
			            break;
			        outstr[ret++] = '%';
					break; 
				default: 
					break; 
			}
			fp++; 
		} 
	}  

	outstr[ret] = '\0';

	return ret;
}

