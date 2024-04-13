/***************************************************************************//**
 * @file
 * @brief Provide stdio retargeting configuration parameters.
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
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

#ifndef __RETARGETSERIALCONFIG_H
#define __RETARGETSERIALCONFIG_H

#include "bsp.h"

/* Override if needed with commandline parameter -DRETARGET_xxx */

#if !defined(RETARGET_USART1)   \
  && !defined(RETARGET_LEUART0) \
  && !defined(RETARGET_USART2)  \
  && !defined(RETARGET_VCOM)
#define RETARGET_VCOM    /* Use the VCOM port by default. */
#endif

#if defined(RETARGET_USART1)
  #define RETARGET_IRQ_NAME    USART1_RX_IRQHandler         /* USART IRQ Handler */
  #define RETARGET_CLK         cmuClock_USART1              /* HFPER Clock */
  #define RETARGET_IRQn        USART1_RX_IRQn               /* IRQ number */
  #define RETARGET_UART        USART1                       /* UART instance */
  #define RETARGET_TX          USART_Tx                     /* Set TX to USART_Tx */
  #define RETARGET_RX          USART_Rx                     /* Set RX to USART_Rx */
  #define RETARGET_LOCATION    USART_ROUTE_LOCATION_LOC2    /* Location of of the USART I/O pins */
  #define RETARGET_TXPORT      gpioPortD                    /* USART transmission port */
  #define RETARGET_TXPIN       7                            /* USART transmission pin */
  #define RETARGET_RXPORT      gpioPortD                    /* USART reception port */
  #define RETARGET_RXPIN       6                            /* USART reception pin */
  #define RETARGET_USART       1                            /* Includes em_usart.h */
  #define RETARGET_PERIPHERAL_ENABLE()

#elif defined(RETARGET_LEUART0)
  #define RETARGET_IRQ_NAME    LEUART0_IRQHandler           /* LEUART IRQ Handler */
  #define RETARGET_CLK         cmuClock_LEUART0             /* LFB Clock */
  #define RETARGET_IRQn        LEUART0_IRQn                 /* IRQ number */
  #define RETARGET_UART        LEUART0                      /* LEUART instance */
  #define RETARGET_TX          LEUART_Tx                    /* Set TX to LEUART_Tx */
  #define RETARGET_RX          LEUART_Rx                    /* Set RX to LEUART_Rx */
  #define RETARGET_TXPORT      gpioPortD                    /* LEUART transmission port */
  #define RETARGET_TXPIN       4                            /* LEUART transmission pin */
  #define RETARGET_RXPORT      gpioPortD                    /* LEUART reception port */
  #define RETARGET_RXPIN       5                            /* LEUART reception pin */
  #define RETARGET_LOCATION    LEUART_ROUTE_LOCATION_LOC0   /* Location of of the LEUART I/O pins */
  #define RETARGET_LEUART      1                            /* Includes em_leuart.h */
  #define RETARGET_PERIPHERAL_ENABLE()

#elif defined(RETARGET_USART2) || defined(RETARGET_VCOM)
  #define RETARGET_IRQ_NAME    USART2_RX_IRQHandler         /* USART IRQ Handler */
  #define RETARGET_CLK         cmuClock_USART2              /* HFPER Clock */
  #define RETARGET_IRQn        USART2_RX_IRQn               /* IRQ number */
  #define RETARGET_UART        USART2                       /* UART instance */
  #define RETARGET_TX          USART_Tx                     /* Set TX to USART_Tx */
  #define RETARGET_RX          USART_Rx                     /* Set RX to USART_Rx */
  #define RETARGET_LOCATION    USART_ROUTE_LOCATION_LOC1    /* Location of of the USART I/O pins */
  #define RETARGET_TXPORT      gpioPortB                    /* USART transmission port */
  #define RETARGET_TXPIN       3                            /* USART transmission pin */
  #define RETARGET_RXPORT      gpioPortB                    /* USART reception port */
  #define RETARGET_RXPIN       4                            /* USART reception pin */
  #define RETARGET_CTSPORT     gpioPortB                    /* USART CTS port */
  #define RETARGET_CTSPIN      5                            /* USART CTS pin  */
  #define RETARGET_RTSPORT     gpioPortB                    /* USART RTS port */
  #define RETARGET_RTSPIN      6                            /* USART RTS pin  */
  #define RETARGET_USART       2                            /* Includes em_usart.h */
#if defined(RETARGET_VCOM)
  #define RETARGET_PERIPHERAL_ENABLE() \
  GPIO_PinModeSet(BSP_BCC_ENABLE_PORT, \
                  BSP_BCC_ENABLE_PIN,  \
                  gpioModePushPull,    \
                  1);
#else
  #define RETARGET_PERIPHERAL_ENABLE()
#endif

#else
#error "Illegal USART/LEUART selection."
#endif

#endif
