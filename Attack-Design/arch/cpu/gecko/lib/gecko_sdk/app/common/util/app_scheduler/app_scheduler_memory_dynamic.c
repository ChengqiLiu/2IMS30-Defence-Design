/***************************************************************************//**
 * @file
 * @brief Application Scheduler Dynamic Memory Management Implementation
 *******************************************************************************
 * # License
 * <b>Copyright 2021 Silicon Laboratories Inc. www.silabs.com</b>
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

#include "app_scheduler_memory.h"
#include "app_scheduler.h"
#include "sl_malloc.h"
#include "app_scheduler_internal.h"

// -----------------------------------------------------------------------------
// Public functions

/***************************************************************************//**
 * Allocate memory for the scheduler
 ******************************************************************************/
sl_status_t app_scheduler_memory_alloc(app_scheduler_task_handle_t *data)
{
  sl_status_t ret = SL_STATUS_OK;
  void *pos = sl_malloc(sizeof(app_scheduler_entry_t));
  if (pos == NULL) {
    ret = SL_STATUS_NO_MORE_RESOURCE;
  } else {
    *data = pos;
  }
  return ret;
}

/***************************************************************************//**
 * Free memory that was allocated for the scheduler
 ******************************************************************************/
sl_status_t app_scheduler_memory_free(app_scheduler_task_handle_t data)
{
  sl_status_t ret = SL_STATUS_OK;
  sl_free((void *)data);
  return ret;
}
