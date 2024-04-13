;/**************************************************************************//**
; * @file
; * @brief    CMSIS Core Device Startup File for
; *           Silicon Labs EFR32MG12P Device Series
; ******************************************************************************
; * # License
; *
; * The licensor of this software is Silicon Laboratories Inc. Your use of this
; * software is governed by the terms of Silicon Labs Master Software License
; * Agreement (MSLA) available at
; * www.silabs.com/about-us/legal/master-software-license-agreement. This
; * software is Third Party Software licensed by Silicon Labs from a third party
; * and is governed by the sections of the MSLA applicable to Third Party
; * Software and the additional terms set forth below.
; *
; *****************************************************************************/
;/*
; ****************************************************************************/
;/*
; * Copyright (c) 2009-2021 Arm Limited. All rights reserved.
; *
; * SPDX-License-Identifier: Apache-2.0
; *
; * Licensed under the Apache License, Version 2.0 (the License); you may
; * not use this file except in compliance with the License.
; * You may obtain a copy of the License at
; *
; * www.apache.org/licenses/LICENSE-2.0
; *
; * Unless required by applicable law or agreed to in writing, software
; * distributed under the License is distributed on an AS IS BASIS, WITHOUT
; * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; * See the License for the specific language governing permissions and
; * limitations under the License.
; */


                PRESERVE8
                THUMB


; Vector Table Mapped to Address 0 at Reset

                AREA     RESET, DATA, READONLY

                AREA     RESET, DATA, READONLY, ALIGN=9
                EXPORT   __Vectors
                EXPORT   __Vectors_End
                EXPORT   __Vectors_Size

__Vectors       DCD      __initial_sp                        ;     Top of Stack
                DCD      Reset_Handler                       ; Reset Handler
                DCD      NMI_Handler                         ; -14 NMI Handler
                DCD      HardFault_Handler                   ; -13 Hard Fault Handler
                DCD      MemManage_Handler                   ; -12 MPU Fault Handler
                DCD      BusFault_Handler                    ; -11 Bus Fault Handler
                DCD      UsageFault_Handler                  ; -10 Usage Fault Handler
                DCD      0                                   ; Reserved
                DCD      0                                   ; Reserved
                DCD      0                                   ; Reserved
                DCD      0                                   ; Reserved
                DCD      SVC_Handler                         ; -5 SVCall Handler
                DCD      DebugMon_Handler                    ; -4 Debug Monitor Handler
                DCD      sl_app_properties                   ; Application properties
                DCD      PendSV_Handler                      ; PendSV Handler
                DCD      SysTick_Handler                     ; SysTick Handler

                ; External Interrupts


                DCD      EMU_IRQHandler                      ; 0: EMU Interrupt
                DCD      FRC_PRI_IRQHandler                  ; 1: FRC_PRI Interrupt
                DCD      WDOG0_IRQHandler                    ; 2: WDOG0 Interrupt
                DCD      WDOG1_IRQHandler                    ; 3: WDOG1 Interrupt
                DCD      FRC_IRQHandler                      ; 4: FRC Interrupt
                DCD      MODEM_IRQHandler                    ; 5: MODEM Interrupt
                DCD      RAC_SEQ_IRQHandler                  ; 6: RAC_SEQ Interrupt
                DCD      RAC_RSM_IRQHandler                  ; 7: RAC_RSM Interrupt
                DCD      BUFC_IRQHandler                     ; 8: BUFC Interrupt
                DCD      LDMA_IRQHandler                     ; 9: LDMA Interrupt
                DCD      GPIO_EVEN_IRQHandler                ; 10: GPIO_EVEN Interrupt
                DCD      TIMER0_IRQHandler                   ; 11: TIMER0 Interrupt
                DCD      USART0_RX_IRQHandler                ; 12: USART0_RX Interrupt
                DCD      USART0_TX_IRQHandler                ; 13: USART0_TX Interrupt
                DCD      ACMP0_IRQHandler                    ; 14: ACMP0 Interrupt
                DCD      ADC0_IRQHandler                     ; 15: ADC0 Interrupt
                DCD      IDAC0_IRQHandler                    ; 16: IDAC0 Interrupt
                DCD      I2C0_IRQHandler                     ; 17: I2C0 Interrupt
                DCD      GPIO_ODD_IRQHandler                 ; 18: GPIO_ODD Interrupt
                DCD      TIMER1_IRQHandler                   ; 19: TIMER1 Interrupt
                DCD      USART1_RX_IRQHandler                ; 20: USART1_RX Interrupt
                DCD      USART1_TX_IRQHandler                ; 21: USART1_TX Interrupt
                DCD      LEUART0_IRQHandler                  ; 22: LEUART0 Interrupt
                DCD      PCNT0_IRQHandler                    ; 23: PCNT0 Interrupt
                DCD      CMU_IRQHandler                      ; 24: CMU Interrupt
                DCD      MSC_IRQHandler                      ; 25: MSC Interrupt
                DCD      CRYPTO0_IRQHandler                  ; 26: CRYPTO0 Interrupt
                DCD      LETIMER0_IRQHandler                 ; 27: LETIMER0 Interrupt
                DCD      AGC_IRQHandler                      ; 28: AGC Interrupt
                DCD      PROTIMER_IRQHandler                 ; 29: PROTIMER Interrupt
                DCD      RTCC_IRQHandler                     ; 30: RTCC Interrupt
                DCD      SYNTH_IRQHandler                    ; 31: SYNTH Interrupt
                DCD      CRYOTIMER_IRQHandler                ; 32: CRYOTIMER Interrupt
                DCD      RFSENSE_IRQHandler                  ; 33: RFSENSE Interrupt
                DCD      FPUEH_IRQHandler                    ; 34: FPUEH Interrupt
                DCD      SMU_IRQHandler                      ; 35: SMU Interrupt
                DCD      WTIMER0_IRQHandler                  ; 36: WTIMER0 Interrupt
                DCD      WTIMER1_IRQHandler                  ; 37: WTIMER1 Interrupt
                DCD      PCNT1_IRQHandler                    ; 38: PCNT1 Interrupt
                DCD      PCNT2_IRQHandler                    ; 39: PCNT2 Interrupt
                DCD      USART2_RX_IRQHandler                ; 40: USART2_RX Interrupt
                DCD      USART2_TX_IRQHandler                ; 41: USART2_TX Interrupt
                DCD      I2C1_IRQHandler                     ; 42: I2C1 Interrupt
                DCD      USART3_RX_IRQHandler                ; 43: USART3_RX Interrupt
                DCD      USART3_TX_IRQHandler                ; 44: USART3_TX Interrupt
                DCD      VDAC0_IRQHandler                    ; 45: VDAC0 Interrupt
                DCD      CSEN_IRQHandler                     ; 46: CSEN Interrupt
                DCD      LESENSE_IRQHandler                  ; 47: LESENSE Interrupt
                DCD      CRYPTO1_IRQHandler                  ; 48: CRYPTO1 Interrupt
                DCD      TRNG0_IRQHandler                    ; 49: TRNG0 Interrupt
                DCD      0                                   ; 50: Reserved

                SPACE   (173 * 4)          ; Remaining Interrupts are left out

__Vectors_End
__Vectors_Size  EQU      __Vectors_End - __Vectors


                AREA     |.text|, CODE, READONLY


; Reset Handler

Reset_Handler   PROC
                EXPORT  Reset_Handler             [WEAK]
                IMPORT   SystemInit
                IMPORT   __main

                LDR      R0, =SystemInit
                BLX      R0
                LDR      R0, =__main
                BX       R0
                ENDP

; The default macro is not used for HardFault_Handler
; because this results in a poor debug illusion.
HardFault_Handler PROC
                EXPORT  HardFault_Handler         [WEAK]
                B        .
                ENDP

; Macro to define default exception/interrupt handlers.
; Default handler are weak symbols with an endless loop.
; They can be overwritten by real handlers.
                MACRO
                Set_Default_Handler  $Handler_Name
$Handler_Name   PROC
                EXPORT  $Handler_Name             [WEAK]
                B        .
                ENDP
                MEND


; Default exception/interrupt handler

                Set_Default_Handler  NMI_Handler
                Set_Default_Handler  MemManage_Handler
                Set_Default_Handler  BusFault_Handler
                Set_Default_Handler  UsageFault_Handler
                Set_Default_Handler  SVC_Handler
                Set_Default_Handler  DebugMon_Handler
                Set_Default_Handler  PendSV_Handler
                Set_Default_Handler  SysTick_Handler


                Set_Default_Handler  EMU_IRQHandler
                Set_Default_Handler  FRC_PRI_IRQHandler
                Set_Default_Handler  WDOG0_IRQHandler
                Set_Default_Handler  WDOG1_IRQHandler
                Set_Default_Handler  FRC_IRQHandler
                Set_Default_Handler  MODEM_IRQHandler
                Set_Default_Handler  RAC_SEQ_IRQHandler
                Set_Default_Handler  RAC_RSM_IRQHandler
                Set_Default_Handler  BUFC_IRQHandler
                Set_Default_Handler  LDMA_IRQHandler
                Set_Default_Handler  GPIO_EVEN_IRQHandler
                Set_Default_Handler  TIMER0_IRQHandler
                Set_Default_Handler  USART0_RX_IRQHandler
                Set_Default_Handler  USART0_TX_IRQHandler
                Set_Default_Handler  ACMP0_IRQHandler
                Set_Default_Handler  ADC0_IRQHandler
                Set_Default_Handler  IDAC0_IRQHandler
                Set_Default_Handler  I2C0_IRQHandler
                Set_Default_Handler  GPIO_ODD_IRQHandler
                Set_Default_Handler  TIMER1_IRQHandler
                Set_Default_Handler  USART1_RX_IRQHandler
                Set_Default_Handler  USART1_TX_IRQHandler
                Set_Default_Handler  LEUART0_IRQHandler
                Set_Default_Handler  PCNT0_IRQHandler
                Set_Default_Handler  CMU_IRQHandler
                Set_Default_Handler  MSC_IRQHandler
                Set_Default_Handler  CRYPTO0_IRQHandler
                Set_Default_Handler  LETIMER0_IRQHandler
                Set_Default_Handler  AGC_IRQHandler
                Set_Default_Handler  PROTIMER_IRQHandler
                Set_Default_Handler  RTCC_IRQHandler
                Set_Default_Handler  SYNTH_IRQHandler
                Set_Default_Handler  CRYOTIMER_IRQHandler
                Set_Default_Handler  RFSENSE_IRQHandler
                Set_Default_Handler  FPUEH_IRQHandler
                Set_Default_Handler  SMU_IRQHandler
                Set_Default_Handler  WTIMER0_IRQHandler
                Set_Default_Handler  WTIMER1_IRQHandler
                Set_Default_Handler  PCNT1_IRQHandler
                Set_Default_Handler  PCNT2_IRQHandler
                Set_Default_Handler  USART2_RX_IRQHandler
                Set_Default_Handler  USART2_TX_IRQHandler
                Set_Default_Handler  I2C1_IRQHandler
                Set_Default_Handler  USART3_RX_IRQHandler
                Set_Default_Handler  USART3_TX_IRQHandler
                Set_Default_Handler  VDAC0_IRQHandler
                Set_Default_Handler  CSEN_IRQHandler
                Set_Default_Handler  LESENSE_IRQHandler
                Set_Default_Handler  CRYPTO1_IRQHandler
                Set_Default_Handler  TRNG0_IRQHandler

                ALIGN


; User setup Stack & Heap

                IF       :LNOT::DEF:__MICROLIB
                IMPORT   __use_two_region_memory
                ENDIF

                EXPORT   __stack_limit
                EXPORT   __initial_sp
                IF       Heap_Size != 0                      ; Heap is provided
                EXPORT   __heap_base
                EXPORT   __heap_limit
                ENDIF

                END
