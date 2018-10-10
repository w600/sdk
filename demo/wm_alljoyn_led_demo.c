/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2013-2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
#include "wm_include.h"
#if DEMO_ALLJOYN_LED

#define AJ_MODULE DUE_LED

#include <stdint.h>
#include <stddef.h>
#include <aj_debug.h>
#include <alljoyn.h>
#include "list.h"
#include "light_if.h"

#define ALLJOYN_LED_DEMO_TASK_SIZE   700
static OS_STK AlljoynLedDemoTaskStk[ALLJOYN_LED_DEMO_TASK_SIZE]; 
struct session_info{
	struct dl_list list;
	uint32_t sessionId;
	char * joiner;
	AJ_BusAttachment* bus;
};
#if 1
struct dl_list session_list;
#define METHOD_TIMEOUT     (1000 * 10)
uint8_t dbgDUE_LED = 0;

void DUE_led_timed(uint32_t msec){
	printf("DUE_led_timed : %d\n", msec);
}

static void DUE_led(light_struct *light)
{
	lightIf_control(*light);
}

static u16 DUE_led_state()
{
	return tls_gpio_read(GPIO_LED1);
}

static const char ServiceName[] = "org.alljoyn.sample.ledservice";
//static const char DaemonServiceName[] = "com.winnermicro.ledctrl";
static const uint16_t ServicePort = 24;
static uint8_t connected = FALSE;


static const char* const testInterface[] = {
    "com.winnermicro.ledctrl.LedCtrlInterface",
    "?Flash msec<u",
    "?On",
    "?Off",
    "?GetState",
    NULL
};


static const AJ_InterfaceDescription testInterfaces[] = {
    testInterface,
    NULL
};

/**
 * Objects implemented by the application
 */
static const AJ_Object AppObjects[] = {
    { "/com/winnermicro/ledctrl/LedCtrlInterface", testInterfaces },
    { NULL }
};

/**
 * Objects implemented by the application. The first member in the AJ_Object structure is the path.
 * The second is the collection of all interfaces at that path.
 */
static const AJ_Object ProxyObjects[] = {
    { "/ledCtrlReplyService", testInterfaces },
    { NULL }
};

/*
 * Message identifiers for the method calls this application implements
 */

#define APP_FLASH   AJ_APP_MESSAGE_ID(0, 0, 0)
#define APP_ON      AJ_APP_MESSAGE_ID(0, 0, 1)
#define APP_OFF     AJ_APP_MESSAGE_ID(0, 0, 2)
#define APP_GET_STATE    AJ_APP_MESSAGE_ID(0, 0, 3)

#define REPLY_ON  AJ_PRX_MESSAGE_ID(0, 0, 1)
#define REPLY_OFF  AJ_PRX_MESSAGE_ID(0, 0, 2)

static AJ_Status AppDoWork()
{
	struct tls_ethif * ethif = tls_netif_get_ethif();
	if(!ethif->status){
		AJ_AlwaysPrintf(("wifi disconnected.\n"));
		return AJ_ERR_CONNECT;
	}
	return AJ_OK;
}

static const char PWD[] = "ABCDEFGH";

static uint32_t PasswordCallback(uint8_t* buffer, uint32_t bufLen)
{
    memcpy(buffer, PWD, sizeof(PWD));
    return sizeof(PWD) - 1;
}

static AJ_Status AppHandleFlash(AJ_Message* msg)
{
    AJ_Message reply;
    uint32_t timeout;
    AJ_UnmarshalArgs(msg, "u", &timeout);
    AJ_AlwaysPrintf(("AppHandleFlash(%u)\n", timeout));

    DUE_led_timed(timeout);


    AJ_MarshalReplyMsg(msg, &reply);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleState(AJ_Message* msg)
{
    AJ_Message reply;
    AJ_AlwaysPrintf(("AppHandleState()\n"));
    AJ_MarshalReplyMsg(msg, &reply);
    return AJ_DeliverMsg(&reply);
}

static AJ_Status AppHandleOnOff(AJ_Message* msg, uint8_t on)
{
    AJ_Message reply;
    light_struct light;
    AJ_AlwaysPrintf(("AppHandleOnOff(%u)\n", on));
	light.state = on;
    DUE_led(&light);
	AJ_AlwaysPrintf(("AppHandleOnOff() msg's senderis %s\n", msg->sender));
    AJ_MarshalReplyMsg(msg, &reply);
    return AJ_DeliverMsg(&reply);
}

static void MakeMethodCall(AJ_BusAttachment* bus, uint32_t msgId, uint32_t sessionId, char* destination)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, msgId, destination, sessionId, 0, METHOD_TIMEOUT);

   // if (status == AJ_OK) {
   //     status = AJ_MarshalArgs(&msg, "s", "Hello World!");
    //}

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_AlwaysPrintf(("MakeMethodCall() destination:%s, sessionId:%d.\n", destination, sessionId));
}

static void AppReplyOnOff(uint8_t on)
{
	if(!connected)
		return;
	AJ_AlwaysPrintf(("AppReplyOnOff(%d) call.\n", on));
	struct session_info * sessionInfo = NULL;
	dl_list_for_each(sessionInfo, &session_list, struct session_info, list){
		MakeMethodCall(sessionInfo->bus, on ? REPLY_ON : REPLY_OFF, sessionInfo->sessionId, sessionInfo->joiner);
	}
}
static AJ_BusAttachment bus;
static void light_status_event_callback(light_struct *light)
{
	AppReplyOnOff(light->state);
}
int tls_stop_alljoyn_calorifier(void){
	uint32_t cpu_sr;
	struct session_info * sessionInfo = NULL;
       cpu_sr = tls_os_set_critical();
	while((sessionInfo=dl_list_first(&session_list, struct session_info, list)) != NULL){
		dl_list_del(&sessionInfo->list);
		AJ_AlwaysPrintf(("tls_mem_free sessionInfo=%p\n", sessionInfo));
		tls_mem_free(sessionInfo->joiner);
		tls_mem_free(sessionInfo);
	}
	tls_os_release_critical(cpu_sr);
	AJ_Disconnect(&bus);
	AJ_AlwaysPrintf(("AllJoyn disconnect\n"));
	connected = FALSE;
	return 0;
}
#define CONNECT_TIMEOUT    (1000 * 120)
#define UNMARSHAL_TIMEOUT  (1000 * 1)
extern u8 *wpa_supplicant_get_mac(void);

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    uint32_t sessionId = 0;
    uint32_t cpu_sr;
    char service_name[50];
    u8* mac = NULL;
    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, ProxyObjects);
    mac = wpa_supplicant_get_mac(); 
    memset(service_name, 0, sizeof(service_name));
    sprintf(service_name, "%s.mac%02X%02X%02X%02X%02X%02X", ServiceName, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    AJ_AlwaysPrintf(("Running service_name: %s, ServicePort : %u\n", service_name, ServicePort));
    while (TRUE) {
        AJ_Message msg;
        struct session_info * sessionInfo = NULL;
        if (!connected) {
            status = AJ_StartService(&bus, NULL, CONNECT_TIMEOUT, FALSE, ServicePort, service_name, AJ_NAME_REQ_DO_NOT_QUEUE, NULL);
            if (status != AJ_OK) {
                continue;
            }
            AJ_AlwaysPrintf(("StartService returned AJ_OK; running %s:%u\n", service_name, ServicePort));
            connected = TRUE;
            AJ_BusSetPasswordCallback(&bus, PasswordCallback);
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                status = AppDoWork();
                if(status == AJ_OK)
                	continue;
            }
            else
            {
                AJ_AlwaysPrintf(("AJ_UnmarshalMsg status = %u\n", status));
            }
        }
        if (status == AJ_OK) {
            switch (msg.msgId) {

            case AJ_METHOD_ACCEPT_SESSION:
                {
                    AJ_AlwaysPrintf(("Accepting...\n"));
                    uint16_t joiner_len = 0;
                    uint16_t port;
                    char* joiner;
                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    status = AJ_BusReplyAcceptSession(&msg, TRUE);
                    //update session id
                    dl_list_for_each(sessionInfo, &session_list, struct session_info, list){
                        if(strcmp(sessionInfo->joiner, joiner) == 0){
                            sessionInfo->sessionId = sessionId;
                            joiner_len = strlen(joiner);
                            break;
                        }
                    }
                    if(joiner_len > 0)
                        break;
                    sessionInfo = tls_mem_alloc(sizeof(struct session_info));
                    if(sessionInfo == NULL)
                        break;
                    joiner_len = strlen(joiner);
                    sessionInfo->sessionId = sessionId;
                    sessionInfo->bus = &bus;
                    sessionInfo->joiner = tls_mem_alloc(joiner_len+1);
                    if(sessionInfo->joiner == NULL)
                    {
                        tls_mem_free(sessionInfo);
                        break;
                    }
                    memset(sessionInfo->joiner, 0, joiner_len+1);
                    memcpy(sessionInfo->joiner, joiner, joiner_len);
                    cpu_sr = tls_os_set_critical();
                    dl_list_add_tail(&session_list, &sessionInfo->list);
                    tls_os_release_critical(cpu_sr);

                    if (status == AJ_OK) {
                        AJ_AlwaysPrintf(("Accepted session session_id=%u joiner=%s\n", sessionId, joiner));
                    } else {
                        AJ_AlwaysPrintf(("AJ_BusReplyAcceptSession: error %d\n", status));
                    }
                }
                break;

            case APP_FLASH:
                status = AppHandleFlash(&msg);
                break;

            case APP_ON:
                AppHandleOnOff(&msg, TRUE);
		//AppReplyOnOff(&bus, TRUE);
                break;

            case APP_OFF:
                AppHandleOnOff(&msg, FALSE);
		//AppReplyOnOff(&bus, FALSE);
                break;
            case APP_GET_STATE:
                AppHandleState(&msg);
                if(DUE_led_state())
                    AppReplyOnOff(TRUE);
                else
                    AppReplyOnOff(FALSE);
                break;
            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                {
                    uint32_t id, reason;
                    u8 isFree = 0;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u", id, reason));
                    dl_list_for_each(sessionInfo, &session_list, struct session_info, list){
                        if(sessionInfo->sessionId == id){
                            isFree = 1;
                            break;
                        }
                    }
                    if(isFree){
                        cpu_sr = tls_os_set_critical();
                        dl_list_del(&sessionInfo->list);
                        tls_os_release_critical(cpu_sr);
                        tls_mem_free(sessionInfo->joiner);
                        tls_mem_free(sessionInfo);
                    }
                }
                status = AJ_ERR_SESSION_LOST;
                break;

            default:
                /*
                 * Pass to the built-in bus message handlers
                 */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }
        /*
         * Unarshaled messages must be closed to free resources
         */
        AJ_CloseMsg(&msg);

        if (status != AJ_OK && status != AJ_ERR_SESSION_LOST) {
            tls_stop_alljoyn_calorifier();
            /*
             * Sleep a little while before trying to reconnect
             */
            AJ_Sleep(10);
        }
    }
//    AJ_AlwaysPrintf(("svclite EXIT %d\n", status));

//    return status;
}
#else

static const char ServiceName[] = "org.alljoyn.bus.samples.simple";
static const char ServicePath[] = "/SimpleService";
static const uint16_t ServicePort = 42;

/*
 * Buffer to hold the full service name. This buffer must be big enough to hold
 * a possible 255 characters plus a null terminator (256 bytes)
 */
static char fullServiceName[AJ_MAX_SERVICE_NAME_SIZE];

uint8_t dbgBASIC_CLIENT = 0;
/**
 * The interface name followed by the method signatures.
 *
 * See also .\inc\aj_introspect.h
 */
static const char* const sampleInterface[] = {
    "org.alljoyn.bus.samples.simple.SimpleInterface",   /* The first entry is the interface name. */
    "?Ping inStr<s",            
    NULL
};

/**
 * A NULL terminated collection of all interfaces.
 */
static const AJ_InterfaceDescription sampleInterfaces[] = {
    sampleInterface,
    NULL
};

/**
 * Objects implemented by the application. The first member in the AJ_Object structure is the path.
 * The second is the collection of all interfaces at that path.
 */
static const AJ_Object AppObjects[] = {
    { ServicePath, sampleInterfaces },
    { NULL }
};

/*
 * The value of the arguments are the indices of the object path in AppObjects (above),
 * interface in sampleInterfaces (above), and member indices in the interface.
 * The 'cat' index is 2. The reason for this is as follows: The first entry in sampleInterface
 * is the interface name. This makes the first index (index 0 of the methods) the second string in
 * sampleInterface[]. The two dummy entries are indices 0 and 1. The index of the method we
 * implement for basic_client, 'cat', is 2 which is the fourth string in the array of strings
 * sampleInterface[].
 *
 * See also .\inc\aj_introspect.h
 */
#define BASIC_CLIENT_CAT AJ_PRX_MESSAGE_ID(0, 0, 0)

#define CONNECT_TIMEOUT    (1000 * 60)
#define UNMARSHAL_TIMEOUT  (1000 * 5)
#define METHOD_TIMEOUT     (100 * 10)

void MakeMethodCall(AJ_BusAttachment* bus, uint32_t sessionId)
{
    AJ_Status status;
    AJ_Message msg;

    status = AJ_MarshalMethodCall(bus, &msg, BASIC_CLIENT_CAT, fullServiceName, sessionId, 0, METHOD_TIMEOUT);

    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", "Hello World!");
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }

    AJ_AlwaysPrintf(("MakeMethodCall() resulted in a status of 0x%04x.\n", status));
}

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint8_t done = FALSE;
    uint32_t sessionId = 0;

    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();
    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(NULL, AppObjects);

    while (!done) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartClientByName(&bus,
                                          NULL,
                                          CONNECT_TIMEOUT,
                                          FALSE,
                                          ServiceName,
                                          ServicePort,
                                          &sessionId,
                                          NULL,
                                          fullServiceName);

            if (status == AJ_OK) {
                AJ_AlwaysPrintf(("StartClient returned %d, sessionId=%u, fullServiceName=%s.\n", status, sessionId, fullServiceName));
                connected = TRUE;

                MakeMethodCall(&bus, sessionId);
            } else {
                AJ_AlwaysPrintf(("StartClient returned 0x%04x.\n", status));
                break;
            }
        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);

        if (AJ_ERR_TIMEOUT == status) {
            continue;
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {
            case AJ_REPLY_ID(BASIC_CLIENT_CAT):
                {
                    AJ_Arg arg;

                    status = AJ_UnmarshalArg(&msg, &arg);

                    if (AJ_OK == status) {
                        AJ_AlwaysPrintf(("'%s.%s' (path='%s') returned '%s'.\n", fullServiceName, "cat",
                                         ServicePath, arg.val.v_string));
                        done = TRUE;
                    } else {
                        AJ_AlwaysPrintf(("AJ_UnmarshalArg() returned status %d.\n", status));
                        /* Try again because of the failure. */
                        MakeMethodCall(&bus, sessionId);
                    }
                }
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                /* A session was lost so return error to force a disconnect. */
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_AlwaysPrintf(("Session lost. ID = %u, reason = %u", id, reason));
                }
                status = AJ_ERR_SESSION_LOST;
                break;

            default:
                /* Pass to the built-in handlers. */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }

        /* Messages MUST be discarded to free resources. */
        AJ_CloseMsg(&msg);

        if (status == AJ_ERR_SESSION_LOST) {
            AJ_AlwaysPrintf(("AllJoyn disconnect.\n"));
            AJ_Disconnect(&bus);
            exit(0);
        }
    }

    AJ_AlwaysPrintf(("Basic client exiting with status %d.\n", status));

    return status;
}
#endif

static void alljoyn_led_demo_task(void *sdata){
	dl_list_init(&session_list);
	lightIf_add_status_event(light_status_event_callback);
	AJ_Main();
}

int tls_start_alljoyn_led_demo(char *buf)
{
	tls_os_task_create(NULL, NULL,
			alljoyn_led_demo_task,
                    NULL,
                    (void *)AlljoynLedDemoTaskStk,          /* 任务栈的起始地址 */
                    ALLJOYN_LED_DEMO_TASK_SIZE * sizeof(u32), /* 任务栈的大小     */
                    DEMO_ALLJOYN_LED_TASK_PRIO,
                    0);
	return WM_SUCCESS;
}

#endif


