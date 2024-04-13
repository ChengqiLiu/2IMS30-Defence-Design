/***************************************************************************//**
 * @file
 * @brief CANopen Emergency (Emcy) Object Service
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc.  Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement.
 * The software is governed by the sections of the MSLA applicable to Micrium
 * Software.
 *
 ******************************************************************************/

/********************************************************************************************************
 ********************************************************************************************************
 *                                               MODULE
 ********************************************************************************************************
 *******************************************************************************************************/

#ifndef _CANOPEN_EMCY_PRIV_H_
#define _CANOPEN_EMCY_PRIV_H_

/********************************************************************************************************
 ********************************************************************************************************
 *                                            INCLUDE FILES
 ********************************************************************************************************
 *******************************************************************************************************/

#include  <cpu/include/cpu.h>
#include  <canopen_cfg.h>

#include  <canopen/include/canopen_emcy.h>

/********************************************************************************************************
 ********************************************************************************************************
 *                                               DEFINES
 ********************************************************************************************************
 *******************************************************************************************************/

#define CANOPEN_EMCY_ERR_CODE_STORAGE_SIZE      (1 + ((CANOPEN_EMCY_MAX_ERR_QTY - 1) / 8))

/********************************************************************************************************
 ********************************************************************************************************
 *                                             DATA TYPES
 ********************************************************************************************************
 *******************************************************************************************************/

/****************************************************************************************************//**
 *                                 CANopen emergency structure
 *
 * @note    (1)  This structure holds the EMCY defintion table and informations to manage the change
 *               detection on all individual EMCY codes.
 *******************************************************************************************************/

typedef struct canopen_emcy {
  CANOPEN_NODE      *NodePtr;                                   ///< link to parent node information
  CANOPEN_EMCY_TBL  *RootUserTblPtr;                            ///< root pointer to user EMCY table
#if (CANOPEN_EMCY_HIST_EN == DEF_ENABLED)
  CANOPEN_EMCY_HIST Hist;                                       ///< EMCY history informations
#endif
  CPU_INT08U        Cnt[CANOPEN_EMCY_REG_QTY];                  ///< Count occurrences of register bits
  CPU_INT08U        Err[CANOPEN_EMCY_ERR_CODE_STORAGE_SIZE];    ///< individual error code status storage
} CANOPEN_EMCY;

/********************************************************************************************************
 ********************************************************************************************************
 *                                         FUNCTION PROTOTYPES
 ********************************************************************************************************
 *******************************************************************************************************/

#if (CANOPEN_EMCY_MAX_ERR_QTY > 0)
void CANopen_EmcyInit(CANOPEN_EMCY     *p_emcy,
                      CANOPEN_NODE     *p_node,
                      CANOPEN_EMCY_TBL *p_root,
                      RTOS_ERR         *p_err);

void CANopen_EmcySetInternal(CANOPEN_EMCY     *p_emcy,
                             CPU_INT08U       err_code_ix,
                             CANOPEN_EMCY_USR *p_usr,
                             RTOS_ERR         *p_err);

void CANopen_EmcyClrInternal(CANOPEN_EMCY *p_emcy,
                             CPU_INT08U   err_code_ix,
                             RTOS_ERR     *p_err);
#endif

/********************************************************************************************************
 ********************************************************************************************************
 *                                               MODULE END
 ********************************************************************************************************
 *******************************************************************************************************/

#endif // _CANOPEN_EMCY_PRIV_H_
