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

/** @addtogroup wm_i2s_demo  wm i2s demo
* @{
*/

/** @addtogroup wm_i2s_demo_struct  wm i2s demo  struct
* @{
*/

#define WM_I2S_TX_DMA_CHANNEL (4)
#define WM_I2S_RX_DMA_CHANNEL (5)

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

uint32_t * i2s_demo_test;

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
void tls_i2s_tx_dma_callback()
{
    TLS_I2S_TX_DISABLE();
    DMA_CHNLCTRL_REG(WM_I2S_TX_DMA_CHANNEL) |= DMA_CHNL_CTRL_CHNL_ON;
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
void tls_i2s_rx_dma_callback()
{
    TLS_I2S_RX_DISABLE();
    tls_mem_free(i2s_demo_test);
}




void tls_i2s_rx_demo_callback()
{
	tls_mem_free(i2s_demo_test);
}

void tls_i2s_tx_demo_callback()
{
    tls_mem_free(i2s_demo_test);
}

/** @} */

void tls_i2s_tx_dma_demo()
{	
	uint16_t i;
	uint32_t * ptr;	
	
	i2s_demo_test = tls_mem_alloc(1024);
	ptr = i2s_demo_test;

	for(i = 0; i < 256; i++)
	{
		*ptr++ = 0xABCD0100 + i;
	}
	tls_i2s_tx_dma(i2s_demo_test, 1024, tls_i2s_tx_dma_callback);
}

void tls_i2s_rx_dma_demo()
{
	i2s_demo_test = tls_mem_alloc(1024);	
	tls_i2s_rx_dma(i2s_demo_test, 1024,  tls_i2s_rx_dma_callback);		
}

void tls_i2s_tx_demo()
{
        uint16_t len;
        uint32_t *ptr = NULL;
        uint32_t * i2s_tx_test = tls_mem_alloc(1024);
		
        if (i2s_tx_test == NULL)
        {
            return;
        }
        for (len = 0; len < 256; len++)
        {
            *ptr++ = 0xABCD0200 + len;
        }        	        
        tls_i2s_tx_block(i2s_tx_test, 1024);
        tls_mem_free(i2s_tx_test);
}

void tls_i2s_rx_demo()
{
    i2s_demo_test = tls_mem_alloc(1024);   
    tls_i2s_rx_nonblock(i2s_demo_test, 1024, tls_i2s_rx_demo_callback);	
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
 *    - \ref 0: transmit
 *    - \ref 1: receiver
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
 *	- \ref 1: mono
 *
 * @param[in]  mode         
 *    - \ref 0: interrupt
 *    - \ref 1: dma
 *
 * @retval            
 *
 * @note              
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
	opts.rx_en = tx_rx & WM_I2S_TX;
	opts.tx_en = tx_rx & WM_I2S_RX;
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

/** @} */

/*** (C) COPYRIGHT 2014 Winner Microelectronics Co., Ltd. ***/
