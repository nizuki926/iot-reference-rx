/**********************************************************************************************************************
 * DISCLAIMER
 * This software is supplied by Renesas Electronics Corporation and is only intended for use with Renesas products. No
 * other uses are authorized. This software is owned by Renesas Electronics Corporation and is protected under all
 * applicable laws, including copyright laws.
 * THIS SOFTWARE IS PROVIDED "AS IS" AND RENESAS MAKES NO WARRANTIES REGARDING
 * THIS SOFTWARE, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. ALL SUCH WARRANTIES ARE EXPRESSLY DISCLAIMED. TO THE MAXIMUM
 * EXTENT PERMITTED NOT PROHIBITED BY LAW, NEITHER RENESAS ELECTRONICS CORPORATION NOR ANY OF ITS AFFILIATED COMPANIES
 * SHALL BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES FOR ANY REASON RELATED TO
 * THIS SOFTWARE, EVEN IF RENESAS OR ITS AFFILIATES HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * Renesas reserves the right, without notice, to make changes to this software and to discontinue the availability of
 * this software. By using this software, you agree to the additional terms and conditions found by accessing the
 * following link:
 * http://www.renesas.com/disclaimer
 *
 * Copyright (C) 2022 Renesas Electronics Corporation. All rights reserved.
 *********************************************************************************************************************/
/**********************************************************************************************************************
 * File Name    : sqnsl.c
 * Description  : Function to execute the AT command (SQNSL).
 *********************************************************************************************************************/

/**********************************************************************************************************************
 * Includes   <System Includes> , "Project Includes"
 *********************************************************************************************************************/
#include "at_command.h"
#include "cellular_private_api.h"

/**********************************************************************************************************************
 * Macro definitions
 *********************************************************************************************************************/

/**********************************************************************************************************************
 * Typedef definitions
 *********************************************************************************************************************/

/**********************************************************************************************************************
 * Exported global variables
 *********************************************************************************************************************/

/**********************************************************************************************************************
 * Private (static) variables and functions
 *********************************************************************************************************************/

/*************************************************************************************************
 * Function Name  @fn            atc_sqnsl
 ************************************************************************************************/
e_cellular_err_t atc_sqnsl(st_cellular_ctrl_t * const p_ctrl, const uint8_t socket_no,
                            const uint8_t ip_version, const uint16_t port)
{
    e_cellular_err_t ret = CELLULAR_SUCCESS;
    uint8_t ip_type = 1;
    uint8_t str[3][10] = {0};

    if (CELLULAR_SOCKET_IP_VERSION_4 != ip_version)
    {
        ip_type = 2;
    }

    sprintf((char *)str[0], "%d", socket_no);    // (&uint8_t[])->(char *)
    sprintf((char *)str[1], "%d", ip_type);      // (&uint8_t[])->(char *)
    sprintf((char *)str[2], "%d", port);         // (&uint8_t[])->(char *)

    const uint8_t * const p_command_arg[CELLULAR_MAX_ARG_COUNT] = {str[0], str[1], str[2]};

    atc_generate(p_ctrl->sci_ctrl.atc_buff,
        (const uint8_t *)&gp_at_command[ATC_LISTENING_SOCKET][0],    // (const uint8_t *const *)->(const uint8_t **)
            (const uint8_t **)&p_command_arg);                      // (const uint8_t *const *)->(const uint8_t **)

    ret = cellular_execute_at_command(p_ctrl, p_ctrl->sci_ctrl.atc_timeout, ATC_RETURN_OK, ATC_LISTENING_SOCKET);

    return ret;
}
/**********************************************************************************************************************
 * End of function atc_sqnsl
 *********************************************************************************************************************/
