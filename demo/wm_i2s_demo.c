/**************************************************************************//**
 * @file     wm_i2s_demo.c
 * @version  
 * @date 
 * @author    
 * @note
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd. All rights reserved.
 *****************************************************************************/
 
#include "wm_i2s.h"
#include "string.h"
#include "wm_debug.h"
#include "wm_irq.h"
#include "wm_config.h"
#include "wm_mem.h"
#include "wm_demo.h"
#include "wm_gpio_afsel.h"

/** @addtogroup wm_i2s_demo  wm i2s demo
* @{
*/

/** @addtogroup wm_i2s_demo_struct  wm i2s demo  struct
* @{
*/

#if DEMO_I2S

#define DEMO_DATA_SIZE        (1024)


enum 
{
    WM_I2S_MODE_INT,
    WM_I2S_MODE_DMA
};

enum
{
    WM_I2S_TX = 1,
    WM_I2S_RX
};

uint32_t i2s_demo_buff[DEMO_DATA_SIZE] = { 0 };
volatile u8 dmaSendDone = 0;

/** @} */


/** @addtogroup wm_i2s_demo_callback_functions  wm i2s demo  callback functions
* @{
*/

/**
 * @brief              i2s dma callback function
 *
 * @param              
 *
 * @return             
 *
 * @note               
 */
void tls_i2s_demo_tx_dma_callback()
{
    dmaSendDone = 1;
}

/**
 * @brief              i2s tx dma callback function
 *
 * @param              
 *
 * @return            
 *
 * @note               
 */
void tls_i2s_demo_rx_dma_callback()
{
    TLS_I2S_RX_DISABLE();
    tls_dma_free(WM_I2S_RX_DMA_CHANNEL);
    printf("recv %d\r\n", DEMO_DATA_SIZE);
    for(u16 i=0; i<DEMO_DATA_SIZE; i++)
    {
        printf("%X ", i2s_demo_buff[i]);
    }
    //This line is needed if the compiler is gcc
    printf("\r\n");
}




void tls_i2s_rx_demo_callback(u16 len)
{
    printf("recv %d\r\n", len);
    for(u16 i=0; i<len; i++) 
    {
        printf("%X ", i2s_demo_buff[i]);
    }
    //This line is needed if the compiler is gcc
    printf("\r\n");
}


/** @} */

void tls_i2s_tx_dma_demo()
{	
    for(u16 len = 0; len < DEMO_DATA_SIZE; len++)
    {
        i2s_demo_buff[len] = 0xA55A55A0+len;
    }
    dmaSendDone = 0;
    tls_i2s_tx_dma(i2s_demo_buff, (DEMO_DATA_SIZE)*sizeof(i2s_demo_buff[0]), tls_i2s_demo_tx_dma_callback);
    printf("send %d\r\n", DEMO_DATA_SIZE);
    do {
        tls_os_time_delay(HZ/100);
    }
    while(dmaSendDone == 0);

    while((tls_reg_read32(HR_I2S_STATUS) & I2S_TX_FIFO_CNT_MASK)>>4);
    DMA_CHNLCTRL_REG(WM_I2S_TX_DMA_CHANNEL) |= DMA_CHNL_CTRL_CHNL_ON;
    tls_dma_free(WM_I2S_TX_DMA_CHANNEL);
    TLS_I2S_TX_DISABLE();
}

void tls_i2s_rx_dma_demo()
{
    memset(i2s_demo_buff, 0, DEMO_DATA_SIZE*sizeof(i2s_demo_buff[0]));
	tls_i2s_rx_dma(i2s_demo_buff, DEMO_DATA_SIZE*sizeof(i2s_demo_buff[0]),  tls_i2s_demo_rx_dma_callback);		
}

void tls_i2s_tx_demo()
{
    for(u16 len = 0; len < DEMO_DATA_SIZE; len++)
    {
        i2s_demo_buff[len] = 0xA55A55A0+len;
    }

    tls_i2s_tx_block(i2s_demo_buff, DEMO_DATA_SIZE);
    printf("send %d\r\n", DEMO_DATA_SIZE);
}

void tls_i2s_rx_demo()
{
    memset(i2s_demo_buff, 0, DEMO_DATA_SIZE*sizeof(i2s_demo_buff[0]));
    tls_i2s_rx_nonblock(i2s_demo_buff, DEMO_DATA_SIZE, tls_i2s_rx_demo_callback);
}



/**
 * @brief              
 *
 * @param[in]  format
 *	- \ref 0: i2s
 *	- \ref 1: msb
 *	- \ref 2: pcma
 *	- \ref 3: pcmb 
 *
 * @param[in]  tx_rx
 *    - \ref 1: transmit
 *    - \ref 2: receive
 *
 * @param[in]  freq
 *    sample rate 
 *
 * @param[in]  datawidth 
 *    - \ref 8: 8 bit
 *    - \ref 16: 16 bit
 *    - \ref 24: 24 bit
 *    - \ref 32: 32 bit 
 *
 * @param[in]  stereo   
 *    - \ref 0: stereo
 *	  - \ref 1: mono
 *
 * @param[in]  mode         
 *    - \ref 0: interrupt
 *    - \ref 1: dma
 *
 * @retval            
 *
 * @note 
 * t-i2s=(0,1,44100,16,0,0)  -- M_I2S send(ISR mode) 
 * t-i2s=(0,1,44100,16,0,1)  -- M_I2S send(DMA mode)
 * t-i2s=(0,2,44100,16,0,0)  -- S_I2S recv(ISR mode)
 * t-i2s=(0,2,44100,16,0,1)  -- S_I2S recv(DMA mode)
 */
int tls_i2s_demo(s8  format,
	             s8  tx_rx,
	             s32 freq,  
	             s8  datawidth, 
	             s8  stereo,
	             s8  mode) 
{
	tls_i2s_options_t  opts;
	
	opts.format = format;
	opts.data_width = datawidth;
	opts.stereo_mono = stereo;
	opts.tx_en = tx_rx & WM_I2S_TX;
	opts.rx_en = tx_rx & WM_I2S_RX;
	opts.sample_rate = freq;
	
	if (format == -1)
	{
		opts.format= I2S_CTRL_FORMAT_I2S;
	}
	else 
	{
		opts.format = (format << I2S_CTRL_FORMAT_Pos);
	}
	
	if (tx_rx == -1)
	{
		opts.tx_en = 1;
		opts.rx_en = 0;
	}
	
	if (freq == -1)
	{
		opts.sample_rate = 8000;
	}
	
	if (datawidth == -1)
	{
		opts.data_width = I2S_CTRL_DATABIT_16;
	}
	else 
	{
		switch(datawidth >> 3)
		{
			case 1:
				opts.data_width = I2S_CTRL_DATABIT_8;
				break;
			case 2:
				opts.data_width = I2S_CTRL_DATABIT_16;
				break;
			case 3:
				opts.data_width = I2S_CTRL_DATABIT_24;
				break;
			case 4:
				opts.data_width = I2S_CTRL_DATABIT_32;
				break;
			default:
				opts.data_width = I2S_CTRL_DATABIT_16;
				break;
		}			
	}
	if (stereo == -1)
	{
	    opts.stereo_mono = I2S_CTRL_STERO;
	}
	else 
	{
		if ((stereo == 0) || (stereo == 1))
		{
			opts.stereo_mono = (stereo << I2S_CTRL_STEREO_MONO_Pos);
		}
		else 
		{
			opts.stereo_mono = I2S_CTRL_STERO;
		}
	}

    //define your own io here.
    if( opts.tx_en )
    {
        wm_i2s_m_ck_config(WM_IO_PB_08);
        wm_i2s_m_do_config(WM_IO_PB_09);
        wm_i2s_m_ws_config(WM_IO_PB_10);
    }
    else
    {
        wm_i2s_s_di_config(WM_IO_PB_14);
        wm_i2s_s_ck_config(WM_IO_PB_15);
        wm_i2s_s_ws_config(WM_IO_PB_16);
    }
    
    printf("\r\n");
	printf("format:%d, tx_en:%d, freq:%d, datawidth:%d, ", opts.format, opts.tx_en, opts.sample_rate, opts.data_width);
    printf("stereo:%d, mode:%d\r\n", opts.stereo_mono, mode);
	tls_i2s_port_init(&opts);

	if (WM_I2S_MODE_INT == mode)
	{
	    if ((tx_rx & WM_I2S_TX) == WM_I2S_TX)
	    {
	        tls_i2s_tx_demo();
	    }
	    if ((tx_rx & WM_I2S_RX) == WM_I2S_RX)
	    {
	        tls_i2s_rx_demo();
	    }
	}
	else if (WM_I2S_MODE_DMA == mode)
	{
	    if ((tx_rx & WM_I2S_TX) == WM_I2S_TX)
	    {
	        tls_i2s_tx_dma_demo();
	    }
	    if ((tx_rx & WM_I2S_RX) == WM_I2S_RX)
	    {
	        tls_i2s_rx_dma_demo();
	    }
	}
    return WM_SUCCESS;
}

#endif
/** @} */

/*** (C) COPYRIGHT 2014 Winner Microelectronics Co., Ltd. ***/
