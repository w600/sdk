/**
 * @file    wm_log.h
 *
 * @brief   Log Module APIs
 *
 * @author  dave
 *
 * Copyright (c) 2019 Winner Microelectronics Co., Ltd.
 */
#ifndef WM_LOG_H
#define WM_LOG_H

#include "elog.h"

/**
 * @defgroup System_APIs System APIs
 * @brief System APIs
 */

/**
 * @addtogroup System_APIs
 * @{
 */

/**
 * @defgroup DEBUG_APIs DEBUG APIs
 * @brief DEBUG APIs
 */

/**
 * @addtogroup DEBUG_APIs
 * @{
 */

/**
 * @brief          output assert level log information
 *
 * @param          String format list and variable parameters
 *
 * @return         None
 *
 * @note           The file contains the file name, function name, 
 *                 and line number information.
 */
#define wm_log_assert                    log_a

/**
 * @brief          output error level log information
 *
 * @param          String format list and variable parameters
 *
 * @return         None
 *
 * @note           None
 */
#define wm_log_error                     log_e

/**
 * @brief          output warning level log information
 *
 * @param          String format list and variable parameters
 *
 * @return         None
 *
 * @note           None
 */
#define wm_log_warn                      log_w

/**
 * @brief          output info level log information
 *
 * @param          String format list and variable parameters
 *
 * @return         None
 *
 * @note           None
 */
#define wm_log_info                      log_i

/**
 * @brief          output raw log information
 *
 * @param          String format list and variable parameters
 *
 * @return         None
 *
 * @note           The log does not have a color format, 
 *                 and the line ending automatically adds a line break.
 */
#define wm_log_raw                       elog_raw

/**
 * @brief          Output log information in hexadecimal and display its ascii code string
 *
 * @param[in]      name,    name for hex object, it will show on log header
 * @param[in]      width,   hex number for every line, such as: 16, 32
 * @param[in]      buf,     hex buffer
 * @param[in]      size,    buffer size
 *
 * @return         None
 *
 * @note           None
 */
#define wm_log_dump                      elog_hexdump


/**
 * @brief          output debug level log information
 *
 * @param          String format list and variable parameters
 *
 * @return         None
 *
 * @note           None
 */
#define wm_log_debug                     log_d

/**
 * @brief          output verbose level log information
 *
 * @param          String format list and variable parameters
 *
 * @return         None
 *
 * @note           None
 */
#define wm_log_verbose                   log_v


/**
 * @brief          initialize the log system
 *
 * @param          None
 *
 * @return         None
 *
 * @note           None
 */
void wm_log_init(void);

/**
 * @}
 */

/**
 * @}
 */

#endif /* end of WM_LOG_H */

