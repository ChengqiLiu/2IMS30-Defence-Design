/***************************************************************************//**
 * @file
 * @brief
 *******************************************************************************
 * # License
 * <b>Copyright 2021 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#include "af.h"

/** @brief Is Color Supported
 *
 * This function will be called to determine whether a color is supported by a
 * device. The color will be specified by hue and saturation.
 *
 * @param hue   Ver.: always
 * @param saturation   Ver.: always
 */
WEAK(bool emberAfPluginColorControlIsColorSupportedCallback(uint8_t hue,
                                                            uint8_t saturation))
{
  return true;
}
