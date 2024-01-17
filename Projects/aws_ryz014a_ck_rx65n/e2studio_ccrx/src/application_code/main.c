/*
FreeRTOS
Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
Modifications Copyright (C) 2023 Renesas Electronics Corporation. or its affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 http://aws.amazon.com/freertos
 http://www.FreeRTOS.org
*/

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"

/* Logging includes. */
#include "iot_logging_task.h"

/* Key provisioning includes. */
#include "aws_dev_mode_key_provisioning.h"

/* Demo includes */
#include "aws_clientcredential.h"
#include "r_cellular_if.h"
#include "demo_config.h"
#include "store.h"
#include "mqtt_agent_task.h"

st_cellular_ctrl_t cellular_ctrl;
extern bool Connect2AP( void );

extern int32_t littlFs_init(void);
bool ApplicationCounter(uint32_t xWaitTime);
signed char vISR_Routine( void );
extern KeyValueStore_t gKeyValueStore;
extern void vStartSimplePubSubDemo( void  );

#if (ENABLE_OTA_UPDATE_DEMO == 1)
    extern void vStartOtaDemo( void );
#endif

#if (ENABLE_FLEET_PROVISIONING_DEMO == 1)
    extern void vStartFleetProvisioningDemo(void);
#endif

#if (ENABLE_DEVICE_LOCATION_DEMO == 1)
    extern void vStartDeviceLocationDemo( void  );
#endif

/**
 * @brief Flag which enables OTA update task in background along with other demo tasks.
 * OTA update task polls regularly for firmware update jobs or acts on a new firmware update
 * available notification from OTA service.
 */
#define appmainINCLUDE_OTA_UPDATE_TASK            ( 1 )


/**
 * @brief Subscribe Publish demo tasks configuration.
 * Subscribe publish demo task shows the basic functionality of connecting to an MQTT broker, subscribing
 * to a topic, publishing messages to a topic and reporting the incoming messages on subscribed topic.
 * Number of subscribe publish demo tasks to be spawned is configurable.
 */
#define appmainMQTT_NUM_PUBSUB_TASKS              ( 2 )
#define appmainMQTT_PUBSUB_TASK_STACK_SIZE        ( 2048 )
#define appmainMQTT_PUBSUB_TASK_PRIORITY          ( tskIDLE_PRIORITY +1 )

/**
 * @brief Stack size and priority for OTA Update task.
 */
#define appmainMQTT_OTA_UPDATE_TASK_STACK_SIZE    ( 4096 )
#define appmainMQTT_OTA_UPDATE_TASK_PRIORITY      ( tskIDLE_PRIORITY )

/**
 * @brief Stack size and priority for MQTT agent task.
 * Stack size is capped to an adequate value based on requirements from MbedTLS stack
 * for establishing a TLS connection. Task priority of MQTT agent is set to a priority
 * higher than other MQTT application tasks, so that the agent can drain the queue
 * as work is being produced.
 */
#define appmainMQTT_AGENT_TASK_STACK_SIZE         ( 6144 )
#define appmainMQTT_AGENT_TASK_PRIORITY           ( tskIDLE_PRIORITY + 2 )

/**
 * @brief Stack size and priority for CLI task.
 */
#define appmainCLI_TASK_STACK_SIZE                ( 6144 )
#define appmainCLI_TASK_PRIORITY                  ( tskIDLE_PRIORITY + 1 )

#define mainLOGGING_TASK_STACK_SIZE         ( configMINIMAL_STACK_SIZE * 6 )
#define mainLOGGING_MESSAGE_QUEUE_LENGTH    ( 15 )
#define mainTEST_RUNNER_TASK_STACK_SIZE    ( configMINIMAL_STACK_SIZE * 8 )
#define UNSIGNED_SHORT_RANDOM_NUMBER_MASK         (0xFFFFUL)

#define CELLULAR_MCC ( 440 )
#define CELLULAR_MNC ( 10 )

#define demoDEVICE_LOCATION_JSON    \
    "{"                             \
    "\"Ip\": {"                     \
        "\"IpAddress\": \"%s\""     \
    "},"                            \
    "\"CellTowers\": {"             \
        "\"Lte\": ["                \
        "{"                         \
            "\"Mcc\": %d,"          \
            "\"Mnc\": %d,"          \
            "\"EutranCid\": %d,"    \
            "\"Tac\": %d"           \
            "}"                     \
        "]"                         \
    "}"                             \
"}"

#define demoDEVICE_LOCATION_JSON_SIZE ( sizeof( demoDEVICE_LOCATION_JSON ) + 128U )

/**
 * @brief Application task startup hook.
 */
void vApplicationDaemonTaskStartupHook( void );

/**
 * @brief Initializes the board.
 */
void prvMiscInitialization( void );

int vGetDeviceLocationInfo( char * buffer);

extern void UserInitialization(void);
extern void CLI_Support_Settings(void);
extern void vUARTCommandConsoleStart( uint16_t usStackSize, UBaseType_t uxPriority );
extern void vRegisterSampleCLICommands( void );

/*-----------------------------------------------------------*/

/**
 * @brief The application entry point from a power on reset is PowerON_Reset_PC()
 * in resetprg.c.
 */
void main_task( void )
{
	int32_t xResults, Time2Wait = 10000;

	#define mainUART_COMMAND_CONSOLE_STACK_SIZE	( configMINIMAL_STACK_SIZE * 6UL )
	/* The priority used by the UART command console task. */
	#define mainUART_COMMAND_CONSOLE_TASK_PRIORITY	( 1 )

	extern void vRegisterSampleCLICommands( void );
	extern void vUARTCommandConsoleStart( uint16_t usStackSize, UBaseType_t uxPriority );
	extern TaskHandle_t xCLIHandle;

	prvMiscInitialization();
	UserInitialization();

	/* Register the standard CLI commands. */
	vRegisterSampleCLICommands();
	vUARTCommandConsoleStart( mainUART_COMMAND_CONSOLE_STACK_SIZE, mainUART_COMMAND_CONSOLE_TASK_PRIORITY );

	xResults = littlFs_init();

	xMQTTAgentInit();

	if (xResults == LFS_ERR_OK)
	{
		xResults = vprvCacheInit();
	}

	if(ApplicationCounter(Time2Wait))
	{
		/* Remove CLI task before going to demo. */
		/* CLI and Log tasks use common resources but are not exclusively controlled. */
		/* For this reason, the CLI task must be deleted before executing the Demo. */
		vTaskDelete(xCLIHandle);

		if( !Connect2AP())
		{
			configPRINTF( ( "Cellular init failed" ) );
		}
		else
		{

			vTaskDelay(300);

			configPRINTF( ( "Initialise the RTOS's TCP/IP stack\n" ) );

			configPRINTF( ( "---------STARTING DEMO---------\r\n" ) );

        #if (ENABLE_FLEET_PROVISIONING_DEMO == 1)
           vStartFleetProvisioningDemo();
        #else
           xSetMQTTAgentState( MQTT_AGENT_STATE_INITIALIZED );
        #endif

        vStartMQTTAgent (appmainMQTT_AGENT_TASK_STACK_SIZE, appmainMQTT_AGENT_TASK_PRIORITY);

#if (ENABLE_DEVICE_LOCATION_DEMO == 0)
        vStartSimplePubSubDemo ();
#else
        vStartDeviceLocationDemo ();
#endif

        #if (ENABLE_OTA_UPDATE_DEMO == 1)
                  vStartOtaDemo();
        #endif
		}
	}

	while( 1 )
	{
		vTaskSuspend( NULL );
	}
}
/*-----------------------------------------------------------*/

void prvMiscInitialization( void )
{
    /* Initialize UART for serial terminal. */
	CLI_Support_Settings();

    /* Start logging task. */
    xLoggingTaskInitialize( mainLOGGING_TASK_STACK_SIZE,
                            tskIDLE_PRIORITY + 2,
                            mainLOGGING_MESSAGE_QUEUE_LENGTH );

}
/*-----------------------------------------------------------*/

void vApplicationDaemonTaskStartupHook( void )
{

}

/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetIdleTaskMemory() to provide the memory that is
 * used by the Idle task. */
void vApplicationGetIdleTaskMemory( StaticTask_t ** ppxIdleTaskTCBBuffer,
                                    StackType_t ** ppxIdleTaskStackBuffer,
                                    uint32_t * pulIdleTaskStackSize )
{
    /* If the buffers to be provided to the Idle task are declared inside this
     * function then they must be declared static - otherwise they will be allocated on
     * the stack and so not exists after this function exits. */
    static StaticTask_t xIdleTaskTCB;
    static StackType_t uxIdleTaskStack[ configMINIMAL_STACK_SIZE ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxIdleTaskTCBBuffer = &xIdleTaskTCB;

    /* Pass out the array that will be used as the Idle task's stack. */
    *ppxIdleTaskStackBuffer = uxIdleTaskStack;

    /* Pass out the size of the array pointed to by *ppxIdleTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}
/*-----------------------------------------------------------*/

/**
 * @brief This is to provide the memory that is used by the RTOS daemon/time task.
 *
 * If configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetTimerTaskMemory() to provide the memory that is
 * used by the RTOS daemon/time task.
 */
void vApplicationGetTimerTaskMemory( StaticTask_t ** ppxTimerTaskTCBBuffer,
                                     StackType_t ** ppxTimerTaskStackBuffer,
                                     uint32_t * pulTimerTaskStackSize )
{
    /* If the buffers to be provided to the Timer task are declared inside this
     * function then they must be declared static - otherwise they will be allocated on
     * the stack and so not exists after this function exits. */
    static StaticTask_t xTimerTaskTCB;
    static StackType_t uxTimerTaskStack[ configTIMER_TASK_STACK_DEPTH ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;

    /* Pass out the array that will be used as the Timer task's stack. */
    *ppxTimerTaskStackBuffer = uxTimerTaskStack;

    /* Pass out the size of the array pointed to by *ppxTimerTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}
/*-----------------------------------------------------------*/

#ifndef iotconfigUSE_PORT_SPECIFIC_HOOKS

/**
 * @brief Warn user if pvPortMalloc fails.
 *
 * Called if a call to pvPortMalloc() fails because there is insufficient
 * free memory available in the FreeRTOS heap.  pvPortMalloc() is called
 * internally by FreeRTOS API functions that create tasks, queues, software
 * timers, and semaphores.  The size of the FreeRTOS heap is set by the
 * configTOTAL_HEAP_SIZE configuration constant in FreeRTOSConfig.h.
 *
 */
    void vApplicationMallocFailedHook()
    {
        configPRINT_STRING( ( "ERROR: Malloc failed to allocate memory\r\n" ) );
        taskDISABLE_INTERRUPTS();

        /* Loop forever */
        for( ; ; )
        {
        }
    }

/*-----------------------------------------------------------*/

/**
 * @brief Loop forever if stack overflow is detected.
 *
 * If configCHECK_FOR_STACK_OVERFLOW is set to 1,
 * this hook provides a location for applications to
 * define a response to a stack overflow.
 *
 * Use this hook to help identify that a stack overflow
 * has occurred.
 *
 */
    void vApplicationStackOverflowHook( TaskHandle_t xTask,
                                        char * pcTaskName )
    {
        configPRINT_STRING( ( "ERROR: stack overflow\r\n" ) );
        portDISABLE_INTERRUPTS();

        /* Unused Parameters */
        ( void ) xTask;
        ( void ) pcTaskName;

        /* Loop forever */
        for( ; ; )
        {
        }
    }
#endif /* iotconfigUSE_PORT_SPECIFIC_HOOKS */
/*-----------------------------------------------------------*/

#if ( ipconfigUSE_LLMNR != 0 ) || ( ipconfigUSE_NBNS != 0 ) || ( ipconfigDHCP_REGISTER_HOSTNAME == 1 )
    /* This function will be called during the DHCP: the machine will be registered
     * with an IP address plus this name. 
     * Note: Please make sure vprvCacheInit() is called before this function, because
	 * it retrieves thingname value from KeyValue table. */
    const char * pcApplicationHostnameHook( void )
    {
#if defined(__TEST__)
        return clientcredentialIOT_THING_NAME;
#else
        if (gKeyValueStore.table[KVS_CORE_THING_NAME].valueLength > 0)
        {
            return gKeyValueStore.table[KVS_CORE_THING_NAME].value;
        }
        else
        {
            return clientcredentialIOT_THING_NAME;
        }
#endif
    }
#endif

bool ApplicationCounter(uint32_t xWaitTime)
{
    TickType_t xCurrent;
    bool DEMO_TEST = pdTRUE;
    const TickType_t xPrintFrequency = pdMS_TO_TICKS( xWaitTime );
    xCurrent = xTaskGetTickCount();
    signed char cRxChar;
    while( xCurrent < xPrintFrequency )
    {
    	vTaskDelay(1);
    	xCurrent = xTaskGetTickCount();

    	cRxChar = vISR_Routine();
    	if ((cRxChar != 0) )
    	{

    		DEMO_TEST = pdFALSE;
    		break;
    	}
    }
    return DEMO_TEST;
}

signed char vISR_Routine( void )
{
	BaseType_t xTaskWokenByReceive = pdFALSE;
	extern signed char cRxedChar;
    return cRxedChar;
}

int vGetDeviceLocationInfo( char * buffer)
{
    e_cellular_err_t cell_ret;
    st_cellular_notice_t cellular_notice = {0};
    st_cellular_ipaddr_t ip_addr;

    cell_ret = R_CELLULAR_GetAPConnectState(&cellular_ctrl, CELLULAR_ENABLE_NETWORK_RESULT_CODE_LEVEL2, &cellular_notice);
    if (CELLULAR_SUCCESS != cell_ret)
    {
        return -1;
    }

    cell_ret = R_CELLULAR_GetPDPAddress(&cellular_ctrl, &ip_addr);
    if (CELLULAR_SUCCESS != cell_ret)
    {
        return -1;
    }

    return snprintf(buffer, demoDEVICE_LOCATION_JSON_SIZE, demoDEVICE_LOCATION_JSON, ip_addr.ipv4, CELLULAR_MCC, CELLULAR_MNC, strtol( cellular_notice.cell_id, NULL, 16 ), strtol( cellular_notice.ta_code, NULL, 16 ) );
}
