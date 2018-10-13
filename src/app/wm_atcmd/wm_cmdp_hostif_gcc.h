/**************************************************************************
 * File Name                   : tls_cmdp_hostif.h
 * Author                      :
 * Version                     :
 * Date                        :
 * Description                 :
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd. 
 * All rights reserved.
 *
 ***************************************************************************/


#ifndef TLS_CMDP_HOSTIF_H
#define TLS_CMDP_HOSTIF_H

#include "tls_wireless.h"
#include "wm_socket.h"
#include "wm_netif.h"
#include "wm_cmdp.h"
#include "wm_uart.h"
#if TLS_CONFIG_HTTP_CLIENT_TASK
#include "wm_http_client.h"
#endif
#include "wm_efuse.h"

/* host interface hardware mode, indicate which port used */
#define HOSTIF_MODE_HSPI       (0)
#define HOSTIF_MODE_UART0      (1) 
#define HOSTIF_MODE_UART1_LS   (2) 
#define HOSTIF_MODE_UART1_HS   (3)
//#define HOSTIF_MODE_UART1      (4)
#if TLS_CONFIG_RMMS
#define HOSTIF_MODE_RMMS_AT    (5)
#endif

#define HOSTIF_HSPI_RI_CMD    0
#define HOSTIF_HSPI_AT_CMD    1
#define HOSTIF_UART0_RI_CMD   2
#define HOSTIF_UART1_AT_CMD   3
#define HOSTIF_UART0_AT_CMD   4
#define HOSTIF_UART1_RI_CMD   5
#if TLS_CONFIG_RMMS
#define HOSTIF_RMMS_AT_CMD    6
#endif

/* ri data format type definition */
#define PACKET_TYPE_DATA      0
#define PACKET_TYPE_RI_CMD    1
#define PACKET_TYPE_AT_CMD    2 

#define HOSTCMD_SYN      0xAA

#define HOSTIF_MSG_TYPE_EVENT  0
#define HOSTIF_MSG_TYPE_CMD    1
#define HOSTIF_MSG_TYPE_RSP    2

/***************************************************************
 * High speed/HSPI DATA/CMD/EVENT/RSP Format definition
 ***************************************************************/

#define HOSTIF_CMD_NOP                 0
#define HOSTIF_CMD_RESET               1
#define HOSTIF_CMD_PS                  2
#define HOSTIF_CMD_RESET_FLASH         3
#define HOSTIF_CMD_PMTF                4
#define HOSTIF_CMD_GPIO                5
#define HOSTIF_CMD_MAC                 6
#define HOSTIF_CMD_VER                 7
#define HOSTIF_CMD_AP_MAC                8
#define HOSTIF_CMD_TEM					9
#define HOSTIF_CMD_WJOIN               0x20
#define HOSTIF_CMD_WLEAVE              0x21
#define HOSTIF_CMD_WSCAN               0x22
#define HOSTIF_CMD_LINK_STATUS         0x23
//#define HOSTIF_CMD_WPSST               0x24
#define HOSTIF_CMD_AP_LINK_STATUS        0x25
#define HOSTIF_CMD_SKCT                0x28
#define HOSTIF_CMD_SKSTT               0x29
#define HOSTIF_CMD_SKCLOSE             0x2A
#define HOSTIF_CMD_SKSDF               0x2B
#define HOSTIF_CMD_ONESHOT				0x2C
#define HOSTIF_CMD_HTTPC				0x2D
#define HOSTIF_CMD_FWUP					0x2E
#define HOSTIF_CMD_WPRT                0x40
#define HOSTIF_CMD_SSID                0x41
#define HOSTIF_CMD_KEY                 0x42
#define HOSTIF_CMD_ENCRYPT             0x43
#define HOSTIF_CMD_BSSID               0x44
#define HOSTIF_CMD_BRD_SSID            0x45
#define HOSTIF_CMD_CHNL                0x46
#define HOSTIF_CMD_WREG                0x47
#define HOSTIF_CMD_WBGR                0x48
#define HOSTIF_CMD_WATC                0x49
#define HOSTIF_CMD_WPSM                0x4A
#define HOSTIF_CMD_WARM                0x4B
#define HOSTIF_CMD_WPS                 0x4C
#define HOSTIF_CMD_AP_SSID               0x4D
#define HOSTIF_CMD_SKSRCIP             0x50
#define HOSTIF_CMD_SKGHBN              0x51
#define HOSTIF_CMD_CHLL                0x52
#define HOSTIF_CMD_WARC                0x53
#define HOSTIF_CMD_WEBS                0x54
#define HOSTIF_CMD_IOM                 0x55
#define HOSTIF_CMD_CMDM                0x56
#define HOSTIF_CMD_PASS                0x57
#define HOSTIF_CMD_CUSTDATA            0x59
#define HOSTIF_CMD_ATPT                0x5A
#define HOSTIF_CMD_CNTPARAM            0x5B
#define HOSTIF_CMD_NIP                 0x60
#define HOSTIF_CMD_ATM                 0x61
#define HOSTIF_CMD_ATRM                0x62
#define HOSTIF_CMD_AOLM                0x63
#define HOSTIF_CMD_PORTM               0x64
#define HOSTIF_CMD_UART                0x65
#define HOSTIF_CMD_ATLT                0x66
#define HOSTIF_CMD_DNS                 0x67
#define HOSTIF_CMD_DDNS                0x68
#define HOSTIF_CMD_UPNP                0x69
#define HOSTIF_CMD_DNAME               0x6A
#define HOSTIF_CMD_AP_ENCRYPT    0x6B
#define HOSTIF_CMD_AP_KEY              0x6C
#define HOSTIF_CMD_AP_CHL              0x6D
#define HOSTIF_CMD_AP_NIP               0x6E
#define HOSTIF_CMD_AP_WBGR          0x6F
#define HOSTIF_CMD_STA_LIST          0x70
#define HOSTIF_CMD_DBG                 0xF0
#define HOSTIF_CMD_REGR                0xF1
#define HOSTIF_CMD_REGW                0xF2
#define HOSTIF_CMD_RFR                 0xF3
#define HOSTIF_CMD_RFW                 0xF4
#define HOSTIF_CMD_FLSR                0xF5
#define HOSTIF_CMD_FLSW                0xF6
#define HOSTIF_CMD_UPDM                0xF7
#define HOSTIF_CMD_UPDD                0xF8
#define HOSTIF_CMD_UPDP                0xF9
#define HOSTIF_CMD_SIN_TX			   0xFA

#define HOSTIF_EVENT_INIT_END          0xE0
#define HOSTIF_EVENT_CRC_ERR           0xE1
#define HOSTIF_EVENT_SCAN_RES          0xE2
#define HOSTIF_EVENT_JOIN_RES          0xE3
#define HOSTIF_EVENT_STA_JOIN          0xE4
#define HOSTIF_EVENT_STA_LEAVE         0xE5
#define HOSTIF_EVENT_LINKUP            0xE6
#define HOSTIF_EVENT_LINKDOWN          0xE7
#define HOSTIF_EVENT_TCP_CONN          0xE8
#define HOSTIF_EVENT_TCP_JOIN          0xE9
#define HOSTIF_EVENT_TCP_DIS           0xEA
#define HOSTIF_EVENT_TX_ERR            0xEB 

#define ATCMD_OP_NULL      1
#define ATCMD_OP_EQ         2    /* = */
#define ATCMD_OP_EP         4    /* =! , update flash*/
#define ATCMD_OP_QU         8    /* =? */
#define RICMD_OP_GET        16
#define RICMD_OP_SET        32
#define RICMD_OP_UF          64

#define ATCMD_PARAM_TYPE_ASSIC  1
#define ATCMD_PARAM_TYPE_HEX  2
#define ATCMD_PARAM_TYPE_DEC  4
#define ATCMD_PARAM_TYPE_OCT  8
#define ATCMD_PARAM_TYPE_BIN  16

struct tls_hostif_hdr {
    u8      sync;
    u8      type;
    u16     length;
    u8      seq_num;
    u8      flag;
    u8      dest_addr;
    u8      chk; 
};

struct tls_hostif_cmd_hdr {
    u8      msg_type;
    u8      code;
    u8      err;
    u8      ext; 
};

struct tls_hostif_ricmd_ext_hdr {
    u32    remote_ip;
    u16    remote_port;
    u16    local_port; 
};

struct tls_hostif_socket_info {
    u32    remote_ip;
    u16    remote_port;
    u16    local_port; 
    u16    socket; 
    u16    proto; 
};

typedef struct _HOSTIF_CMD_PARAMS_PS {
    u8      ps_type;
    u8      wake_type;
    u16     delay_time;
    u16     wake_time;
} HOSTIF_CMD_PARAMS_PS;

typedef struct _HOSTIF_CMD_PARAMS_GPIO {
    u8      num;
    u8      direct;
    u8      status;
}__attribute__((packed))HOSTIF_CMD_PARAMS_GPIO;

typedef struct _HOSTIF_CMD_PARAMS_SKCT {
    u32     timeout; 
    u8      ip_addr[4];
    u8      proto;
    u8      client;
    u16     port;
    char     host_name[32];
    u8      host_len;
    u16     localport;
    enum tls_cmd_mode mode;
}__attribute__((packed))HOSTIF_CMD_PARAMS_SKCT;

typedef struct _HOSTIF_CMD_PARAMS_SKSTT {
    u8      socket;
}__attribute__((packed))HOSTIF_CMD_PARAMS_SKSTT;

typedef struct _HOSTIF_CMD_PARAMS_SKCLOSE {
    u8      socket;
}__attribute__((packed))HOSTIF_CMD_PARAMS_SKCLOSE;

typedef struct _HOSTIF_CMD_PARAMS_SKSDF {
    u8      socket;
}__attribute__((packed))HOSTIF_CMD_PARAMS_SKSDF;

typedef struct _HOSTIF_CMD_PARAMS_WPRT {
    u8      type;
}__attribute__((packed))HOSTIF_CMD_PARAMS_WPRT;

typedef struct _HOSTIF_CMD_PARAMS_SSID {
    u8      ssid_len;
    u8      ssid[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_SSID;

typedef struct _HOSTIF_CMD_PARAMS_KEY {
    u8      format;
    u8      index;
    u8      key_len;
    u8      key[64];
}__attribute__((packed))HOSTIF_CMD_PARAMS_KEY;

typedef struct _HOSTIF_CMD_PARAMS_ENCRYPT {
    u8      mode;
}__attribute__((packed))HOSTIF_CMD_PARAMS_ENCRYPT;

typedef struct _HOSTIF_CMD_PARAMS_BSSID {
    u8      enable;
    u8      bssid[6];
}__attribute__((packed))HOSTIF_CMD_PARAMS_BSSID;

typedef struct _HOSTIF_CMD_PARAMS_BRD_SSID {
    u8      enable;
}__attribute__((packed))HOSTIF_CMD_PARAMS_BRD_SSID;

typedef struct _HOSTIF_CMD_PARAMS_CHNL {
    u8      enable;
    u8      channel;
}__attribute__((packed))HOSTIF_CMD_PARAMS_CHNL;

typedef struct _HOSTIF_CMD_PARAMS_WREG {
    u16     region;
}__attribute__((packed))HOSTIF_CMD_PARAMS_WREG;

typedef struct _HOSTIF_CMD_PARAMS_WBGR {
    u8      mode;
    u8      rate;
}__attribute__((packed))HOSTIF_CMD_PARAMS_WBGR;

typedef struct _HOSTIF_CMD_PARAMS_WATC {
    u8      enable;
}__attribute__((packed))HOSTIF_CMD_PARAMS_WATC;

typedef struct _HOSTIF_CMD_PARAMS_WPSM {
    u8      enable;
}__attribute__((packed))HOSTIF_CMD_PARAMS_WPSM;

typedef struct _HOSTIF_CMD_PARAMS_WARM {
    u8      enable;
}__attribute__((packed))HOSTIF_CMD_PARAMS_WARM;

typedef  struct _HOSTIF_CMD_PARAMS_WPS {
    u8      mode;
    u8      pin_len;
    u8      pin[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_WPS;

typedef struct _HOSTIF_CMD_PARAMS_NIP {
    u8      type;
    u8      ip[4];
    u8      nm[4];
    u8      gw[4];
    u8      dns[4];
}__attribute__((packed))HOSTIF_CMD_PARAMS_NIP;

typedef struct _HOSTIF_CMD_PARAMS_ATM {
    u8      mode;
}__attribute__((packed))HOSTIF_CMD_PARAMS_ATM;

typedef struct _HOSTIF_CMD_PARAMS_ATRM {
    u32 timeout; 
    u8  ip_addr[4];
    u8 proto;
    u8 client;
    u16 port;
    char host_name[32];
    u8  host_len;
    u16 localport;
}__attribute__((packed))HOSTIF_CMD_PARAMS_ATRM;

typedef struct _HOSTIF_CMD_PARAMS_AOLM {
    u8      enable;
    u8      ssid_len;
    u8      ssid[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_AOLM;

typedef struct _HOSTIF_CMD_PARAMS_PORTM {
    u8      mode;
}__attribute__((packed))HOSTIF_CMD_PARAMS_PORTM;

typedef struct _HOSTIF_CMD_PARAMS_UART {
    u8      baud_rate[3];
    u8      char_len;
    u8      stopbit;
    u8      parity;
    u8      flow_ctrl;
}__attribute__((packed))HOSTIF_CMD_PARAMS_UART;

typedef struct _HOSTIF_CMD_PARAMS_ATLT {
    u16      length;
}__attribute__((packed))HOSTIF_CMD_PARAMS_ATLT;

typedef struct _HOSTIF_CMD_PARAMS_DNS {
    u8      length;
    u8      name[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_DNS;

typedef struct _HOSTIF_CMD_PARAMS_DDNS {
    u8      enable;
    u8      user_len;
    u8      user[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_DDNS;

typedef struct _HOSTIF_CMD_PARAMS_UPNP {
    u8      enable;
}__attribute__((packed))HOSTIF_CMD_PARAMS_UPNP;

typedef struct _HOSTIF_CMD_PARAMS_DNAME {
    u8      length;
    u8      name[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_DNAME;

typedef struct _HOSTIF_CMD_PARAMS_DBG {
    u32      dbg_level;
}__attribute__((packed))HOSTIF_CMD_PARAMS_DBG;

typedef struct _HOSTIF_CMD_PARAMS_REGR {
    u32      reg_base_addr;
    u8      length;
}__attribute__((packed))HOSTIF_CMD_PARAMS_REGR;

typedef struct _HOSTIF_CMD_PARAMS_REGW {
    u32      reg_base_addr;
    u8      length;
    u32     v[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_REGW;

typedef struct _HOSTIF_CMD_PARAMS_RFR {
    u16      reg_base_addr;
    u8      length;
}__attribute__((packed))HOSTIF_CMD_PARAMS_RFR;

typedef struct _HOSTIF_CMD_PARAMS_RFW {
    u16      reg_base_addr;
    u8      length;
    u16     v[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_RFW;

typedef struct _HOSTIF_CMD_PARAMS_FLSR {
    u32      reg_base_addr;
    u8      length;
}__attribute__((packed))HOSTIF_CMD_PARAMS_FLSR;

typedef struct _HOSTIF_CMD_PARAMS_FLSW {
    u32      reg_base_addr;
    u8      length;
    u32     v[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_FLSW;

typedef struct _HOSTIF_CMD_PARAMS_UPDM {
    u8      mode;
    u8      src;/* 标识来自at 0, 还是ri 1 */
}__attribute__((packed))HOSTIF_CMD_PARAMS_UPDM;

typedef struct _HOSTIF_CMD_PARAMS_UPDD {
    u16     size;
    u8      data[1];
}__attribute__((packed))HOSTIF_CMD_PARAMS_UPDD; 
 
 typedef struct _HOSTIF_CMD_PARAMS_ONESHOT {
    u8      status;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_ONESHOT;

 typedef struct HOSTIF_CMD_PARAMS_HTTPC {
/* 	u8		verb;
    u8      url_len;
	u16		data_len;
	u8      url[1];*/
	u8		verb;
    u8      url_len;
	u16		data_len;
	u8      *url;
    u8      *data;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_HTTPC;

 typedef struct HOSTIF_CMD_PARAMS_WJOIN {
 	enum tls_cmd_mode mode;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_WJOIN;

 typedef struct HOSTIF_CMD_PARAMS_WSCAN {
 	enum tls_cmd_mode mode;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_WSCAN;

 typedef struct HOSTIF_CMD_PARAMS_SKSND {
 	u8      socket;
    u16     size;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_SKSND;

 typedef struct HOSTIF_CMD_PARAMS_SKRCV {
 	u8      socket;
    u16     size;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_SKRCV;

 typedef struct HOSTIF_CMD_PARAMS_SKRPTM {
 	u8      mode;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_SKRPTM;

 typedef struct HOSTIF_CMD_PARAMS_SKGHBN {
 	u8      ipstr[1];
 }__attribute__((packed))HOSTIF_CMD_PARAMS_SKGHBN;

 typedef struct HOSTIF_CMD_PARAMS_CHANNEL_LIST {
 	u16      channellist;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_CHANNEL_LIST;

 typedef struct HOSTIF_CMD_PARAMS_WARC {
 	u8      autoretrycnt;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_WARC;

 typedef struct HOSTIF_CMD_PARAMS_ATPT {
 	u16      period;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_ATPT;

 typedef struct HOSTIF_CMD_PARAMS_ESPC {
 	u8      escapechar;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_ESPC;

 typedef struct HOSTIF_CMD_PARAMS_ESPT {
 	u16      escapeperiod;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_ESPT;

 typedef struct HOSTIF_CMD_PARAMS_WEBS {
 	u8      autorun;
    u16     portnum;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_WEBS;

 typedef struct HOSTIF_CMD_PARAMS_IOM {
 	u8      mode;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_IOM;

 typedef struct HOSTIF_CMD_PARAMS_CMDM {
 	u8      mode;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_CMDM;

 typedef struct HOSTIF_CMD_PARAMS_PASS {
 	u8      length;
    u8      password[1];
 }__attribute__((packed))HOSTIF_CMD_PARAMS_PASS;

 typedef struct HOSTIF_CMD_PARAMS_UPDP {
 	u8      mode;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_UPDP;

 typedef struct HOSTIF_CMD_PARAMS_TXG {
 	u8      tx_gain[TX_GAIN_LEN];
 }__attribute__((packed))HOSTIF_CMD_PARAMS_TXG;

typedef struct HOSTIF_CMD_PARAMS_TXGR{
	u8 tx_rate;
	u8 txr_gain[3];
}__attribute__((packed))HOSTIF_CMD_PARAMS_TXGR;

 typedef struct HOSTIF_CMD_PARAMS_MAC {
 	u8      length;
    u8      macaddr[6];
 }__attribute__((packed))HOSTIF_CMD_PARAMS_MAC;

 typedef struct HOSTIF_CMD_PARAMS_SPIF {
 	u8      mode;
    u8      len;
    u8      data[1];
 }__attribute__((packed))HOSTIF_CMD_PARAMS_SPIF;

 typedef struct HOSTIF_CMD_PARAMS_LPCHL {
 	u8      channel;
	u8      bandwidth;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_LPCHL;

 typedef struct HOSTIF_CMD_PARAMS_LPTSTR {
 	u32      channel;
    u32      packetcount;
    u32      psdulen;
    u32      txgain;
    u32      datarate;
	u32      rifs;
	u32      greenfield;
	u32      gimode;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_LPTSTR;

 typedef struct HOSTIF_CMD_PARAMS_LPPSTR {
 	u32      param;
    u32      start;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_LPPSTR;

 typedef struct HOSTIF_CMD_PARAMS_LPPSTP {
 	u32      mismatch;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_LPPSTP;
  typedef struct HOSTIF_CMD_PARAMS_WIDTH {
    u32      freq;
    u32      dividend;
 }	__attribute__((packed))HOSTIF_CMD_PARAMS_WIDTH;

  typedef struct HOSTIF_CMD_PARAMS_RXSIN {
	u32      rxlen;
	u32		 isprint;
 }	__attribute__((packed))HOSTIF_CMD_PARAMS_RXSIN;
  typedef struct HOSTIF_CMD_PARAMS_PING {
	u8      *ip;
	u32		 timeLimt;
	u32		 cnt;
	u32		 start;
 }	__attribute__((packed))HOSTIF_CMD_PARAMS_PING;

  typedef  struct HOSTIF_CMD_PARAMS_THT {
	u32		*tok;
 }	__attribute__((packed))HOSTIF_CMD_PARAMS_THT;
 typedef  struct _HOSTIF_CMD_PARAMS_TXLO{
    u32 txlo;
 }	__attribute__((packed))HOSTIF_CMD_PARAMS_TXLO;
 typedef  struct _HOSTIF_CMD_PARAMS_TXIQ{
    u32 txiqgain;
    u32 txiqphase;
 }	__attribute__((packed))HOSTIF_CMD_PARAMS_TXIQ;
 typedef struct _HOSTIF_CMD_PARAMS_FREQERR{
    int freqerr;
 }	__attribute__((packed))HOSTIF_CMD_PARAMS_FREQERR;
 typedef  struct _HOSTIF_CMD_PARAMS_VCGCTRL{
    int vcg;
 }__attribute__((packed))HOSTIF_CMD_PARAMS_VCGCTRL;

 typedef struct _HOSTIF_CMDRSP_PARAMS_TEM {
    u8      offsetLen;
    u8      offset[8];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_TEM; 

 union HOSTIF_CMD_PARAMS_UNION{

        HOSTIF_CMD_PARAMS_PS ps;

        HOSTIF_CMD_PARAMS_GPIO gpio;

        HOSTIF_CMD_PARAMS_SKCT skct;

        HOSTIF_CMD_PARAMS_SKSTT skstt;

        HOSTIF_CMD_PARAMS_SKCLOSE skclose;

        HOSTIF_CMD_PARAMS_SKSDF sksdf;

        HOSTIF_CMD_PARAMS_WPRT wprt;

        HOSTIF_CMD_PARAMS_SSID ssid;

        HOSTIF_CMD_PARAMS_KEY key;

        HOSTIF_CMD_PARAMS_ENCRYPT encrypt;

        HOSTIF_CMD_PARAMS_BSSID bssid;

        HOSTIF_CMD_PARAMS_BRD_SSID brd_ssid;

        HOSTIF_CMD_PARAMS_CHNL channel;

        HOSTIF_CMD_PARAMS_WREG wreg;

        HOSTIF_CMD_PARAMS_WBGR wbgr;

        HOSTIF_CMD_PARAMS_WATC watc;

        HOSTIF_CMD_PARAMS_WPSM wpsm;

        HOSTIF_CMD_PARAMS_WARM warm;

        HOSTIF_CMD_PARAMS_WPS wps;

        HOSTIF_CMD_PARAMS_NIP nip;

        HOSTIF_CMD_PARAMS_ATM atm;

        HOSTIF_CMD_PARAMS_ATRM atrm;

        HOSTIF_CMD_PARAMS_AOLM aolm;

        HOSTIF_CMD_PARAMS_PORTM portm;

        HOSTIF_CMD_PARAMS_UART uart;

        HOSTIF_CMD_PARAMS_ATLT atlt;

        HOSTIF_CMD_PARAMS_DNS dns;

        HOSTIF_CMD_PARAMS_DDNS ddns;

        HOSTIF_CMD_PARAMS_UPNP upnp;

        HOSTIF_CMD_PARAMS_DNAME dname;

        HOSTIF_CMD_PARAMS_DBG dbg;

        HOSTIF_CMD_PARAMS_REGR regr;

        HOSTIF_CMD_PARAMS_REGW regw;

        HOSTIF_CMD_PARAMS_RFR rfr;

        HOSTIF_CMD_PARAMS_RFW rfw;

        HOSTIF_CMD_PARAMS_FLSR flsr;

        HOSTIF_CMD_PARAMS_FLSW flsw;

        HOSTIF_CMD_PARAMS_UPDM updm;

        HOSTIF_CMD_PARAMS_UPDD updd; 
		
		HOSTIF_CMD_PARAMS_ONESHOT oneshot;

		HOSTIF_CMD_PARAMS_HTTPC httpc;

        HOSTIF_CMDRSP_PARAMS_TEM tem;

        HOSTIF_CMD_PARAMS_WJOIN wjoin;

        HOSTIF_CMD_PARAMS_WSCAN wscan;

        HOSTIF_CMD_PARAMS_SKSND sksnd;

        HOSTIF_CMD_PARAMS_SKRCV skrcv;

        HOSTIF_CMD_PARAMS_SKRPTM skrptm;

        HOSTIF_CMD_PARAMS_SKGHBN skghbn;

        HOSTIF_CMD_PARAMS_CHANNEL_LIST channel_list;

        HOSTIF_CMD_PARAMS_WARC warc;

        HOSTIF_CMD_PARAMS_ATPT atpt;

        HOSTIF_CMD_PARAMS_ESPC espc;

        HOSTIF_CMD_PARAMS_ESPT espt;

        HOSTIF_CMD_PARAMS_WEBS webs;

        HOSTIF_CMD_PARAMS_IOM iom;

        HOSTIF_CMD_PARAMS_CMDM cmdm;

        HOSTIF_CMD_PARAMS_PASS pass;

        HOSTIF_CMD_PARAMS_UPDP updp;

        HOSTIF_CMD_PARAMS_TXG txg;
        HOSTIF_CMD_PARAMS_TXGR txgr;

        HOSTIF_CMD_PARAMS_MAC mac;

        HOSTIF_CMD_PARAMS_SPIF spif;

        HOSTIF_CMD_PARAMS_LPCHL lpchl;

        HOSTIF_CMD_PARAMS_LPTSTR lptstr;

        HOSTIF_CMD_PARAMS_LPPSTR lppstr;

        HOSTIF_CMD_PARAMS_LPPSTP lppstp;
		
	HOSTIF_CMD_PARAMS_WIDTH  width;
	HOSTIF_CMD_PARAMS_RXSIN  rxsin;
	HOSTIF_CMD_PARAMS_TXLO   txLO;
	HOSTIF_CMD_PARAMS_TXIQ    txIQ;
	HOSTIF_CMD_PARAMS_FREQERR  FreqErr;
	HOSTIF_CMD_PARAMS_VCGCTRL vcgCtrl;
	HOSTIF_CMD_PARAMS_PING  ping;
	HOSTIF_CMD_PARAMS_THT	tht;
    }; 
struct tls_hostif_cmd {
    struct tls_hostif_cmd_hdr cmd_hdr;
    /* command body */
    union HOSTIF_CMD_PARAMS_UNION params; 
};


typedef struct _HOSTIF_CMDRSP_PARAMS_MAC {
    u8      addr[6];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_MAC; 

typedef struct _HOSTIF_CMDRSP_PARAMS_VER {
    u8      hw_ver[6];
    u8      fw_ver[4];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_VER; 

typedef struct _HOSTIF_CMDRSP_PARAMS_JOIN {
    u8      bssid[6];
    u8      type;
    u8      channel;
    u8      encrypt;
    u8      ssid_len;
    u8      ssid[32];
    u8      rssi;
    u8      result;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_JOIN;

typedef struct _HOSTIF_CMDRSP_PARAMS_LKSTT {
    u8      status;
    u8      ip[4];
    u8      nm[4];
    u8      gw[4];
    u8      dns1[4];
    u8      dns2[4];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_LKSTT; 

typedef struct _HOSTIF_CMDRSP_PARAMS_SKCT {
    u8      socket;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SKCT; 

struct hostif_cmdrsp_skstt_ext {
    u8      socket;
    u8      status;
    u8      host_ipaddr[4];
    u16      remote_port;
    u16      local_port; 
}__attribute__((packed));

typedef struct _HOSTIF_CMDRSP_PARAMS_SKSTT {
    u8      number;
    struct hostif_cmdrsp_skstt_ext ext[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SKSTT; 

typedef struct _HOSTIF_CMDRSP_PARAMS_WPRT {
    u8      type;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WPRT;

typedef struct _HOSTIF_CMDRSP_PARAMS_SSID {
    u8      ssid_len;
    u8      ssid[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SSID;

typedef struct _HOSTIF_CMDRSP_PARAMS_KEY {
    u8      format;
    u8      index;
    u8      key_len;
    u8      key[64];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_KEY;

typedef struct _HOSTIF_CMDRSP_PARAMS_ENCRYPT {
    u8      mode;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_ENCRYPT;

typedef struct _HOSTIF_CMDRSP_PARAMS_BSSID {
    u8      enable;
    u8      bssid[6];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_BSSID;

typedef struct _HOSTIF_CMDRSP_PARAMS_BRD_SSID {
    u8      enable;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_BRD_SSID;

typedef struct _HOSTIF_CMDRSP_PARAMS_CHNL {
    u8      enable;
    u8      channel;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_CHNL; 

typedef struct _HOSTIF_CMDRSP_PARAMS_WREG {
    u16     region;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WREG; 

typedef struct _HOSTIF_CMDRSP_PARAMS_WBGR {
    u8      mode;
    u8      rate;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WBGR; 

typedef struct _HOSTIF_CMDRSP_PARAMS_WATC {
    u8      enable;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WATC; 

typedef struct _HOSTIF_CMDRSP_PARAMS_WPSM {
    u8      enable;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WPSM; 

typedef struct _HOSTIF_CMDRSP_PARAMS_WARM {
    u8      enable;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WARM; 

typedef struct _HOSTIF_CMDRSP_PARAMS_WPS {
    u8      result;
    u8      pin_len;
    u8      pin[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WPS; 

typedef struct _HOSTIF_CMDRSP_PARAMS_NIP {
    u8      type;
    u8      ip[4];
    u8      nm[4];
    u8      gw[4];
    u8      dns[4];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_NIP; 

typedef struct _HOSTIF_CMDRSP_PARAMS_ATM {
    u8      mode;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_ATM;


typedef struct _HOSTIF_CMDRSP_PARAMS_ATRM {
    u32 timeout; 
    u8  ip_addr[4];
    u8 proto;
    u8 client;
    u16 port;
    char host_name[32];
    u8  host_len;
    u16 localport;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_ATRM; 

typedef struct _HOSTIF_CMDRSP_PARAMS_AOLM {
    u8      enable;
    u8      ssid_len;
    u8      ssid[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_AOLM; 

typedef struct _HOSTIF_CMDRSP_PARAMS_PORTM {
    u8      mode;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_PORTM; 

typedef struct _HOSTIF_CMDRSP_PARAMS_UART {
    u8      baud_rate[3];
    u8      char_len;
    u8      stopbit;
    u8      parity;
    u8      flow_ctrl;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_UART; 

typedef struct _HOSTIF_CMDRSP_PARAMS_ATLT {
    u16     length;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_ATLT; 

typedef struct _HOSTIF_CMDRSP_PARAMS_DNS {
    u8      length;
    u8      name[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_DNS;

typedef struct _HOSTIF_CMDRSP_PARAMS_DDNS {
    u8      enable;
    u8      user_len;
    u8      user[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_DDNS;

typedef struct _HOSTIF_CMDRSP_PARAMS_UPNP {
    u8      enable;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_UPNP;

typedef struct _HOSTIF_CMDRSP_PARAMS_DNAME {
    u8      length;
    u8      name[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_DNAME;

typedef struct _HOSTIF_CMDRSP_PARAMS_DBG {
    u32      dbg_level;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_DBG;

typedef struct _HOSTIF_CMDRSP_PARAMS_REGR {
    u8       length;
    u32      value[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_REGR;

typedef struct _HOSTIF_CMDRSP_PARAMS_RFR {
    u8       length;
    u16      value[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_RFR;

typedef struct _HOSTIF_CMDRSP_PARAMS_FLSR {
    u8       length;
    u32      value[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_FLSR;

typedef struct _HOSTIF_CMDRSP_PARAMS_UPDM {
    u8      mode;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_UPDM;

typedef struct _HOSTIF_CMDRSP_PARAMS_SKSND {
    u16      size;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SKSND;

typedef struct _HOSTIF_CMDRSP_PARAMS_SKRCV {
    u8      socket;
    u16      size;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SKRCV;

typedef struct _HOSTIF_CMDRSP_PARAMS_SKRPTM {
    u8      mode;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SKRPTM;

typedef struct _HOSTIF_CMDRSP_PARAMS_SKSRCIP {
    u8      ipvalue[4];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SKSRCIP;

typedef struct _HOSTIF_CMDRSP_PARAMS_SKGHBN {
    u8  h_addr_list[4];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SKGHBN;

typedef struct _HOSTIF_CMDRSP_PARAMS_CHANNEL_LIST {
    u16  channellist;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_CHANNEL_LIST;

typedef struct _HOSTIF_CMDRSP_PARAMS_WARC {
    u8  autoretrycnt;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WARC;

typedef struct _HOSTIF_CMDRSP_PARAMS_CNTPARAM_BSSID_DIS {
    u8      bssid_enable;
    u8      ssid_len;
    u8      key_len;
    u8      ssid_key[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_CNTPARAM_BSSID_DIS;

typedef struct _HOSTIF_CMDRSP_PARAMS_CNTPARAM_BSSID_EN {
    u8      bssid_enable;
    u8      bssid[6];
    u8      key_len;
    u8      key[64];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_CNTPARAM_BSSID_EN;

typedef struct _HOSTIF_CMDRSP_PARAMS_ATPT {
    u16  period;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_ATPT;

typedef struct _HOSTIF_CMDRSP_PARAMS_ESPC {
    u8  escapechar;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_ESPC;

typedef struct _HOSTIF_CMDRSP_PARAMS_ESPT {
    u16  escapeperiod;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_ESPT;

typedef struct _HOSTIF_CMDRSP_PARAMS_WEBS {
    u8  autorun;
    u16 portnum;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_WEBS;

typedef struct _HOSTIF_CMDRSP_PARAMS_IOM {
    u8  mode;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_IOM;

typedef struct _HOSTIF_CMDRSP_PARAMS_CMDM {
    u8  mode;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_CMDM;

typedef struct _HOSTIF_CMDRSP_PARAMS_PASS {
    u8  length;
    u8  password[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_PASS;

typedef struct _HOSTIF_CMDRSP_PARAMS_ONESHOT {
    u8  status;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_ONESHOT;

typedef struct _HOSTIF_CMDRSP_PARAMS_HTTPC {
    u32  psession;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_HTTPC;

typedef struct _HOSTIF_CMDRSP_PARAMS_TXG {
    u8      tx_gain[TX_GAIN_LEN];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_TXG;
 typedef struct _HOSTIF_CMDRSP_PARAMS_TXGR {
 	u8      tx_rate;
         u8      txr_gain[3];
 }__attribute__((packed))HOSTIF_CMDRSP_PARAMS_TXGR;

typedef struct _HOSTIF_CMDRSP_PARAMS_SPIF {
    u8      mode;
    u8      len;
    u8      data[1];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_SPIF;

typedef struct _HOSTIF_CMDRSP_PARAMS_LPCHL {
    u8      channel;
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_LPCHL;

typedef struct _HOSTIF_CMDRSP_PARAMS_CUSTDATA {
    u8      length;
    u8      data[65];
}__attribute__((packed))HOSTIF_CMDRSP_PARAMS_CUSTDATA;

#if TLS_CONFIG_AP
 typedef struct _HOSTIF_CMDRSP_PARAMS_STALIST {
    u8      sta_num;
    u8      data[163];
 }	__attribute__((packed))HOSTIF_CMDRSP_PARAMS_STALIST;
#endif
 typedef  struct _HOSTIF_CMDRSP_PARAMS_TXLO{
    u32 txlo;
 }	__attribute__((packed))HOSTIF_CMDRSP_PARAMS_TXLO;
 typedef  struct _HOSTIF_CMDRSP_PARAMS_TXIQ{
    u32 txiqgain;
    u32 txiqphase;
 }	__attribute__((packed))HOSTIF_CMDRSP_PARAMS_TXIQ;
  typedef  struct _HOSTIF_CMDRSP_PARAMS_FREQERR{
    int freqerr;
 }	__attribute__((packed))HOSTIF_CMDRSP_PARAMS_FREQERR;
  typedef  struct _HOSTIF_CMDRSP_PARAMS_VCGCTRL{
    int vcg;
 }	__attribute__((packed))HOSTIF_CMDRSP_PARAMS_VCGCTRL;

union HOSTIF_CMDRSP_PARAMS_UNION{
        HOSTIF_CMDRSP_PARAMS_MAC mac;

        HOSTIF_CMDRSP_PARAMS_VER ver; 

        HOSTIF_CMDRSP_PARAMS_JOIN join;

        HOSTIF_CMDRSP_PARAMS_LKSTT lkstt; 

        HOSTIF_CMDRSP_PARAMS_SKCT skct; 

        HOSTIF_CMDRSP_PARAMS_SKSTT skstt; 

        HOSTIF_CMDRSP_PARAMS_WPRT wprt;

        HOSTIF_CMDRSP_PARAMS_SSID ssid;

        HOSTIF_CMDRSP_PARAMS_KEY key;

        HOSTIF_CMDRSP_PARAMS_ENCRYPT encrypt;

        HOSTIF_CMDRSP_PARAMS_BSSID bssid;

        HOSTIF_CMDRSP_PARAMS_BRD_SSID brd_ssid;

        HOSTIF_CMDRSP_PARAMS_CHNL channel; 

        HOSTIF_CMDRSP_PARAMS_WREG wreg; 

        HOSTIF_CMDRSP_PARAMS_WBGR wbgr; 

        HOSTIF_CMDRSP_PARAMS_WATC watc; 

        HOSTIF_CMDRSP_PARAMS_WPSM wpsm; 

        HOSTIF_CMDRSP_PARAMS_WARM warm; 

        HOSTIF_CMDRSP_PARAMS_WPS wps; 

        HOSTIF_CMDRSP_PARAMS_NIP nip; 

        HOSTIF_CMDRSP_PARAMS_ATM atm; 

        HOSTIF_CMDRSP_PARAMS_ATRM atrm; 

        HOSTIF_CMDRSP_PARAMS_AOLM aolm; 

        HOSTIF_CMDRSP_PARAMS_PORTM portm; 

        HOSTIF_CMDRSP_PARAMS_UART uart; 

        HOSTIF_CMDRSP_PARAMS_ATLT atlt; 

        HOSTIF_CMDRSP_PARAMS_DNS dns;

        HOSTIF_CMDRSP_PARAMS_DDNS ddns;

        HOSTIF_CMDRSP_PARAMS_UPNP upnp;

        HOSTIF_CMDRSP_PARAMS_DNAME dname;

        HOSTIF_CMDRSP_PARAMS_DBG dbg;

        HOSTIF_CMDRSP_PARAMS_REGR regr;

        HOSTIF_CMDRSP_PARAMS_RFR rfr;

        HOSTIF_CMDRSP_PARAMS_FLSR flsr;

        HOSTIF_CMDRSP_PARAMS_UPDM updm;

        HOSTIF_CMDRSP_PARAMS_SKSND sksnd;

        HOSTIF_CMDRSP_PARAMS_SKRCV skrcv;

        HOSTIF_CMDRSP_PARAMS_SKRPTM skrptm;

        HOSTIF_CMDRSP_PARAMS_SKSRCIP sksrcip;

        HOSTIF_CMDRSP_PARAMS_SKGHBN skghbn;

        HOSTIF_CMDRSP_PARAMS_CHANNEL_LIST channel_list;

        HOSTIF_CMDRSP_PARAMS_WARC warc;

        HOSTIF_CMDRSP_PARAMS_CNTPARAM_BSSID_DIS cntparam_bssid_dis;

        HOSTIF_CMDRSP_PARAMS_CNTPARAM_BSSID_EN cntparam_bssid_en;

        HOSTIF_CMDRSP_PARAMS_ATPT atpt;

        HOSTIF_CMDRSP_PARAMS_ESPC espc;

        HOSTIF_CMDRSP_PARAMS_ESPT espt;

        HOSTIF_CMDRSP_PARAMS_WEBS webs;

        HOSTIF_CMDRSP_PARAMS_IOM iom;

        HOSTIF_CMDRSP_PARAMS_CMDM cmdm;

        HOSTIF_CMDRSP_PARAMS_PASS pass;

        HOSTIF_CMDRSP_PARAMS_ONESHOT oneshot;

        HOSTIF_CMDRSP_PARAMS_HTTPC httpc;

        HOSTIF_CMDRSP_PARAMS_TEM tem;

        HOSTIF_CMDRSP_PARAMS_TXG txg;

	HOSTIF_CMDRSP_PARAMS_TXGR txgr;

        HOSTIF_CMDRSP_PARAMS_SPIF spif;

        HOSTIF_CMDRSP_PARAMS_LPCHL lpchl;

        HOSTIF_CMDRSP_PARAMS_CUSTDATA custdata;

#if TLS_CONFIG_AP
        HOSTIF_CMDRSP_PARAMS_STALIST stalist;
#endif
	HOSTIF_CMDRSP_PARAMS_TXLO  txLO;
	HOSTIF_CMDRSP_PARAMS_TXIQ  txIQ;
	HOSTIF_CMDRSP_PARAMS_FREQERR FreqErr;
	HOSTIF_CMDRSP_PARAMS_VCGCTRL vcgCtrl;
    } ; 
struct tls_hostif_cmdrsp {
    struct tls_hostif_hdr hdr;
    struct tls_hostif_cmd_hdr cmd_hdr;
    /* command body */
    union HOSTIF_CMDRSP_PARAMS_UNION params; 
};


typedef struct _HOSTIF_EVENT_PARAMS_SCAN_RES {
    u8 num;
    u8 data[1];
}__attribute__((packed))HOSTIF_EVENT_PARAMS_SCAN_RES;

typedef struct _HOSTIF_EVENT_PARAMS_JOIN_RES {
    u8 res;
    u8 bssid[6];
    u8 type;
    u8 channel;
    u8 energy;
    u8 ssid_len;
    u8 ssid[1];
}__attribute__((packed))HOSTIF_EVENT_PARAMS_JOIN_RES;

typedef struct _HOSTIF_EVENT_PARAMS_TCP_CONN {
    u8 socket;
    u8 res;
}__attribute__((packed))HOSTIF_EVENT_PARAMS_TCP_CONN;

typedef struct _HOSTIF_EVENT_PARAMS_TCP_JOIN {
    u8 socket;
}__attribute__((packed))HOSTIF_EVENT_PARAMS_TCP_JOIN;

typedef struct _HOSTIF_EVENT_PARAMS_TCP_DIS {
    u8 socket;
}__attribute__((packed))HOSTIF_EVENT_PARAMS_TCP_DIS;

struct tls_hostif_event {
    struct tls_hostif_hdr hdr;
    struct tls_hostif_cmd_hdr cmd_hdr;
    /* event body */
    union {
        HOSTIF_EVENT_PARAMS_SCAN_RES scan_res;

        HOSTIF_EVENT_PARAMS_JOIN_RES join_res;

        HOSTIF_EVENT_PARAMS_TCP_CONN tcp_conn;

        HOSTIF_EVENT_PARAMS_TCP_JOIN tcp_join;

        HOSTIF_EVENT_PARAMS_TCP_DIS tcp_dis;
    } params;

};

struct tls_hostif_data {
    struct tls_hostif_hdr hdr;
    struct tls_hostif_cmd_hdr cmd_hdr;
    u8     data[0]; 
};

struct tls_hostif_extaddr {
    u32    ip_addr;
    u16    remote_port;
    u16    local_port;
};

struct tls_hostif_tx_msg {
    struct dl_list list;
    /* message type: HOSTIF_TX_MSG_XXX */
    u8 type;
    u32 time;
    u16 offset;
    union { 
        struct msg_event_info {
            char  *buf;
            u16 buflen;
        } msg_event;
        struct msg_cmdrsp_info {
            char *buf;
            u16 buflen;
        } msg_cmdrsp;
        struct msg_tcp_info {
            void *p;
            u8 sock;
        } msg_tcp;
        struct msg_udp_info {
            void *p;
            u8 sock;
            u16 port;
            u16 localport;
            ip_addr_t ip_addr;
        } msg_udp; 
    } u; 
}; 

#define HOSTIF_TX_MSG_TYPE_EVENT       0
#define HOSTIF_TX_MSG_TYPE_CMDRSP      1
#define HOSTIF_TX_MSG_TYPE_UDP         2
#define HOSTIF_TX_MSG_TYPE_TCP         3

#define TLS_SOCKET_RECV_BUF_SIZE   512

#define ATCMD_MAX_ARG      10
#define ATCMD_NAME_MAX_LEN 10

struct tls_atcmd_token_t {
    char   name[ATCMD_NAME_MAX_LEN];
    u32   op;
    char  *arg[ATCMD_MAX_ARG];
    u32   arg_found; 
    enum  tls_cmd_mode cmd_mode;
};
struct tls_cmd_t {
    char   *at_name;
    s16 ri_cmd_id;
    u8  op_flag;
    u8  at_arg_len;
    u16 ri_set_len;
    int (* proc_func)(u8 set_opt, u8 update_flash, union HOSTIF_CMD_PARAMS_UNION *cmd, union HOSTIF_CMDRSP_PARAMS_UNION * cmdrsp);
};

typedef void  (*hostif_send_tx_msg_callback)(u8 hostif_mode, struct tls_hostif_tx_msg *tx_msg, bool is_event);

#define UART_ATCMD_BIT_WSCAN     (0)
#define UART_ATCMD_BIT_WJOIN     (1)
#define UART_ATCMD_BIT_SKCT      (2)

struct tls_hostif {
    tls_os_timer_t          *tx_timer;
    //struct dl_list          tx_msg_list;
    //struct dl_list          tx_event_msg_list; 
    //struct tls_hspi         *hspi;
    //struct tls_uart    *uart0;
    //struct tls_uart    *uart1;
    hostif_send_tx_msg_callback hspi_send_tx_msg_callback;
    hostif_send_tx_msg_callback uart_send_tx_msg_callback;
    tls_os_sem_t            *uart_atcmd_sem;
	u16                     uart_atcmd_bits;
    //u8 hspi_port_set;
    //u8 uart0_port_set;
    //u8 uart1_port_set;

    //u8   uart1_atcmd_snd_skt;
    //u8   uart1_atcmd_rec_skt;

    u8 last_scan;
    enum tls_cmd_mode last_scan_cmd_mode;
    u8 last_join;
    enum tls_cmd_mode last_join_cmd_mode;

    /*  indicate use which port: SYS_HOSTIF_XXX */
    u8 hostif_mode; 

    u32 uart_atlt;
    u32 uart_atpt;
    /* uart at cmd loopback control */
    u8 uart_insdisp;
    u8 reserved[3];
	/*uart escape*/
    u8  escape_char;
    u8  escape_reserved;	
    u16 escape_pt;

    u8 hspi_tx_seq;
	u8 rptmode; /*0:host inquire, 1:auto report*/
    u8 reserved1[2];
#if TLS_CONFIG_RMMS
    u8 rmms_status;
    u8 rmms_addr[6];
    u8 reserved2;
#endif
};

struct rmms_msg {
	u8   SrcAddr[6];
    u8   CmdStr[512]; 
};

struct tls_hostif *tls_get_hostif(void);
struct tls_hostif_tx_msg *tls_hostif_get_tx_msg(void);
int tls_hostif_process_cmdrsp(u8 hostif_type, char *cmdrsp, u32 cmdrsp_size);
void tls_hostif_fill_hdr(struct tls_hostif *hif,
        struct tls_hostif_hdr *hdr,
        u8 type, u16 length, u8 flag, u8 dest_addr, u8 chk);

void tls_hostif_fill_cmdrsp_hdr(struct tls_hostif_cmdrsp *cmdrsp,
        u8 code, u8 err, u8 ext);
int tls_hostif_hdr_check(u8 *buf, u32 length);
int tls_hostif_cmd_handler(u8 cmd_type, char *buf, u32 length);
int tls_hostif_send_event_init_cmplt(void);
int tls_hostif_send_event_scan_cmplt(struct tls_scan_bss_t *scan_res,
        enum tls_cmd_mode cmd_mode);

int tls_hostif_send_event_linkdown(void);
int tls_hostif_send_event_sta_join(void);
int tls_hostif_send_event_sta_leave(void);
int tls_hostif_send_event_crc_err(void);
int tls_hostif_send_event_tcp_conn(u8 socket, u8 res);
int tls_hostif_send_event_tcp_join(u8 socket);
int tls_hostif_send_event_tcp_dis(u8 socket);
int tls_hostif_send_event_wjoin_success(void);
int tls_hostif_send_event_wjoin_failed(void);

int tls_hostif_init(void);
int tls_hostif_recv_data(struct tls_hostif_tx_msg *tx_msg);
int tls_hostif_set_net_status_callback(void);
int tls_hostif_send_data(struct tls_hostif_socket_info *skt_info, char *buf, u32 buflen);
int tls_hostif_create_default_socket(void);
int tls_hostif_close_default_socket(void);
struct tls_uart_circ_buf * tls_hostif_get_recvmit(int socket_num);
int tls_cmd_create_socket(struct tls_cmd_socket_t *skt,
        enum tls_cmd_mode cmd_mode);
int tls_cmd_close_socket(u8 skt_num);
int tls_cmd_get_socket_status(u8 socket, u8 *buf, u32 bufsize);
int tls_cmd_get_socket_state(u8 socket, u8 * state, struct tls_skt_status_ext_t *skt_ext);
int tls_cmd_set_default_socket(u8 socket);
u8 tls_cmd_get_default_socket(void);
#if TLS_CONFIG_HTTP_CLIENT_TASK
void tls_hostif_http_client_recv_callback(HTTP_SESSION_HANDLE pSession, CHAR * data, u32 totallen, u32 datalen);
void tls_hostif_http_client_err_callback(HTTP_SESSION_HANDLE pSession, int err);
#endif
int atcmd_err_resp(char *buf, int err_code);
int atcmd_ok_resp(char *buf);
static int atcmd_nop_proc(struct tls_atcmd_token_t *tok, char *res_resp, u32 *res_len);

int tls_atcmd_parse(struct tls_atcmd_token_t *tok, char *buf, u32 len);
int tls_hostif_atcmd_exec(
        struct tls_atcmd_token_t *tok,
        char *res_rsp, u32 *res_len);
int atcmd_filter_quotation(u8 **keyInfo, u8 *inbuf);
int tls_hostif_ricmd_exec(char *buf, u32 length, char *cmdrsp_buf, u32 *cmdrsp_size);
void free_tx_msg_buffer(struct tls_hostif_tx_msg *tx_msg);

#if TLS_CONFIG_RMMS
/*************************************************************************** 
* Function: tls_rmms_start
* Description: Start remote manager server.
* 
* Input:  None
* 
* Output: None
* 
* Return: The rmms error code:
*             RMMS_ERR_SUCCESS - No error
*             RMMS_ERR_MEM - Out of memory
*             RMMS_ERR_LINKDOWN - The NIF is inactive
* 
* Date : 2015-7-20
****************************************************************************/
s8 tls_rmms_start(void);

/*************************************************************************** 
* Function: tls_rmms_stop
* Description: Disable remote manager server.
* 
* Input:  None
* 
* Output: None
* 
* Return: None
* 
* Date : 2015-7-20
****************************************************************************/
void tls_rmms_stop(void);
#endif

void hostif_wscan_cmplt(void);
#endif /* end of TLS_CMDP_HOSTIF_H */

