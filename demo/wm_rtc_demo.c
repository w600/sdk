#include <string.h>
#include "wm_include.h"
#include "wm_demo.h"
#include "wm_rtc.h"

#if DEMO_RTC



static void demo_rtc_clock_irq(void *arg)
{
	struct tm tblock;
	tls_get_rtc(&tblock);
	printf("rtc clock, sec=%d,min=%d,hour=%d,mon=%d,year=%d\n",tblock.tm_sec,tblock.tm_min,tblock.tm_hour,tblock.tm_mon,tblock.tm_year);	
}


int rtc_demo(void)
{
	struct tm tblock;
	
	tblock.tm_year = 17;
	tblock.tm_mon = 11;
	tblock.tm_mday = 20;
	tblock.tm_hour = 14;
	tblock.tm_min = 30;
	tblock.tm_sec = 0;
	tls_set_rtc(&tblock);
	
	tls_rtc_isr_register(demo_rtc_clock_irq, NULL);
	tblock.tm_year = 17;
	tblock.tm_mon = 11;
	tblock.tm_mday = 20;
	tblock.tm_hour = 14;
	tblock.tm_min = 30;
	tblock.tm_sec = 20;
	tls_rtc_timer_start(&tblock);
	
	while(1)
	{
		tls_os_time_delay(200);
		tls_get_rtc(&tblock);
		printf("rtc cnt, sec=%02d,min=%02d,hour=%02d,mon=%02d,year=%02d\n",tblock.tm_sec,tblock.tm_min,tblock.tm_hour,tblock.tm_mon,tblock.tm_year);
	}

	return WM_SUCCESS;
}



#endif



