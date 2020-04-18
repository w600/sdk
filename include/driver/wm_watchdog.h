/**
 * @file    wm_watchdog.h
 *
 * @brief   watchdog Driver Module
 *
 * @author  dave
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd.
 */
#ifndef WM_WATCHDOG_H
#define WM_WATCHDOG_H

/**
 * @defgroup Driver_APIs Driver APIs
 * @brief Driver APIs
 */

/**
 * @addtogroup Driver_APIs
 * @{
 */

/**
 * @defgroup WDG_Driver_APIs WDG Driver APIs
 * @brief WDG driver APIs
 */

/**
 * @addtogroup WDG_Driver_APIs
 * @{
 */

/**
 * @brief          This function is used to clear watchdog irq in case watchdog reset.
 *
 * @param          None
 *
 * @return         None
 *
 * @note           None
 */
void tls_watchdog_clr(void);

/**
 * @brief          This function is used to init and start the watchdog.
 *
 * @param[in]      usec    microseconds
 *
 * @return         None
 *
 * @note           None
 */
void tls_watchdog_init(u32 usec);

/**
 * @brief          This function is used to start calculating elapsed time. 
 *
 * @param[in]      None
 *
 * @return         elapsed time, unit:millisecond
 *
 * @note           None
 */
void tls_watchdog_start_cal_elapsed_time(void);


/**
 * @brief          This function is used to stop calculating & return elapsed time. 
 *
 * @param[in]     none
 *
 * @return         elapsed time, unit:millisecond
 *
 * @note           None
 */
u32 tls_watchdog_stop_cal_elapsed_time(void);


/**
 * @brief          This function is used to reset the system.
 *
 * @param          None
 *
 * @return         None
 *
 * @note           None
 */
void tls_sys_reset(void);

/**
 * @}
 */

/**
 * @}
 */

#endif /* WM_WATCHDOG_H */

