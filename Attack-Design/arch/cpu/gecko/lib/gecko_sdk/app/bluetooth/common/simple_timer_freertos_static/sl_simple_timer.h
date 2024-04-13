/***************************************************************************//**
 * @file
 * @brief Simple timer service based on FreeRTOS with static allocation
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * SPDX-License-Identifier: Zlib
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 ******************************************************************************/
#ifndef SL_SIMPLE_TIMER_H
#define SL_SIMPLE_TIMER_H

#include "FreeRTOS.h"
#include "timers.h"
#include "sl_status.h"

// Forward declaration
typedef struct sl_simple_timer sl_simple_timer_t;

/***************************************************************************//**
 * Expected prototype of the user's callback function which is called when a
 * timer expires.
 *
 * @param timer Pointer to the timer handle.
 * @param data An extra parameter for the user application.
 ******************************************************************************/
typedef void (*sl_simple_timer_callback_t)(sl_simple_timer_t *timer, void *data);

/// Timer structure
struct sl_simple_timer {
  StaticTimer_t static_timer;
  TimerHandle_t handle;
  sl_simple_timer_callback_t callback;
  void *callback_data;
  sl_simple_timer_t *next;
  bool periodic;
};

/***************************************************************************//**
 * Start timer or restart if it is running already.
 *
 * @param[in] timer Pointer to the timer.
 * @param[in] timeout_ms Timer timeout, in milliseconds.
 * @param[in] callback Callback function that is called when timeout expires.
 * @param[in] callback_data Pointer to user data that will be passed to callback.
 * @param[in] is_periodic Reload timer when it expires if true.
 *
 * @return Status of the operation.
 ******************************************************************************/
sl_status_t sl_simple_timer_start(sl_simple_timer_t *timer,
                                  uint32_t timeout_ms,
                                  sl_simple_timer_callback_t callback,
                                  void *callback_data,
                                  bool is_periodic);

/***************************************************************************//**
 * Stop running timer.
 *
 * @param[in] timer Pointer to the timer.
 *
 * @return Status of the operation.
 ******************************************************************************/
sl_status_t sl_simple_timer_stop(sl_simple_timer_t *timer);

#endif // SL_SIMPLE_TIMER_H
