/***************************************************************************//**
 * Copyright 2021 Silicon Laboratories Inc. www.silabs.com
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available here[1]. This software is distributed to you in
 * Source Code format and is governed by the sections of the MSLA applicable to
 * Source Code.
 *
 * [1] www.silabs.com/about-us/legal/master-software-license-agreement
 *
 ******************************************************************************/
#ifndef SL_WSRCP_H
#define SL_WSRCP_H

#include <stdint.h>
#include <stdbool.h>
#include <cmsis_os2.h>
#include <em_device.h>

#if defined(EUSART_PRESENT)
#include <em_eusart.h>
#else
#include <em_usart.h>
#endif

#include "sl_ring.h"

struct ws_mac_ctxt;

enum {
    RX_UART = 1 << 0,
};

struct sl_wsrcp_app {
#if defined(EUSART_PRESENT)
    EUSART_TypeDef *sdk_uart;
#else
    USART_TypeDef *sdk_uart;
#endif
    osMutexId_t uart_tx_lock;
    uint8_t rx_buf_data[4096];
    struct ring rx_buf;
    int irq_rxof_cnt;

    osEventFlagsId_t main_events;
    osThreadId_t main_task;

    struct sl_wsrcp_mac *rcp_mac;
};

// This global variable is necessary for IRQ handling. Beside this use case,
// please never use it.
extern struct sl_wsrcp_app g_rcp_ctxt;

void wisun_rcp_init(void);

#endif
