/**
 * @file    wm_uart_timer.h
 *
 * @brief   Timer for uart Module
 *
 * @author  dave
 *
 * Copyright (c) 2015 Winner Microelectronics Co., Ltd.
 */

#ifndef WM_UART_TIMER_H
#define WM_UART_TIMER_H
#include "wm_uart_task.h"

/**
 * @brief          stop timer
 *
 * @param[in]      None
 *
 * @return         None
 *
 * @note           None
 */
void tls_timer2_stop(void);

/**
 * @brief          start timer
 *
 * @param[in]      *uart
 * @param[in]      timeout
 *
 * @return         None
 *
 * @note           None
 */
void tls_timer2_start(struct tls_uart *uart, u32 timeout);


#endif /* end of WM_UART_TIMER_H */
