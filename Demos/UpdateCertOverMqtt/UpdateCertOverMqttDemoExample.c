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

/* Standard includes. */
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"

/* Demo Config */
#include "demo_config.h"

/* coreJSON includes */
#include "core_json.h"

/* mbedTLS include for configuring threading functions */
#include "mbedtls/threading.h"
#include "threading_alt.h"

/* corePKCS11 includes. */
#include "core_pkcs11.h"
#include "core_pkcs11_config.h"
#include "core_pkcs11_config_defaults.h"

/* MQTT agent task API. */
#include "mqtt_agent_task.h"

/* Demo includes. */
#include "mqtt_pkcs11_demo_helpers.h"
#include "pkcs11_operations.h"
#include "store.h"

/**
 * These configurations are required. Throw compilation error if it is not
 * defined.
 */
#ifndef democonfigROOT_CA_PEM
    #error "Please define Root CA certificate of the MQTT broker(democonfigROOT_CA_PEM) in demo_config.h."
#endif

/**
 * @brief Size of AWS IoT Thing name buffer.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_CreateThing.html#iot-CreateThing-request-thingName
 */
#define ucdemoMAX_THING_NAME_LENGTH                128

#define ucdemoMAX_CSR_SUBJECT_NAME_LENGTH          128

#define ucdemoCSR_REQUEST_TOPIC_FORMAT             "management/topic/%s/csr_res"

#define ucdemoCSR_REQUEST_TOPIC_BUFFER_LENGTH      ( sizeof( ucdemoCSR_REQUEST_TOPIC_FORMAT ) + ucdemoMAX_THING_NAME_LENGTH + 10U )

#define ucdemoCRT_TOPIC_FORMAT                      "management/topic/%s/crt"

#define ucdemoCRT_TOPIC_BUFFER_LENGTH              ( sizeof( ucdemoCRT_TOPIC_FORMAT ) + ucdemoMAX_THING_NAME_LENGTH + 10U )

/**
 * @brief The maximum number of times to run the loop in this demo.
 *
 * @note The demo loop is attempted to re-run only if it fails in an iteration.
 * Once the demo loop succeeds in an iteration, the demo exits successfully.
 */
#ifndef fpdemoMAX_DEMO_LOOP_COUNT
    #define ucdemoMAX_DEMO_LOOP_COUNT    ( 3 )
#endif

/**
 * @brief Time in seconds to wait between retries of the demo loop if
 * demo loop fails.
 */
#define ucdemoDELAY_BETWEEN_DEMO_RETRY_ITERATIONS_SECONDS    ( 5 )

/**
 * @brief Size of buffer in which to hold the certificate signing request (CSR).
 */
#define ucdemoCSR_BUFFER_LENGTH                              2048

/**
 * @brief Size of buffer in which to hold the certificate.
 */
#define ucdemoCERT_BUFFER_LENGTH                             2048

/**
 * @brief Size of buffer in which to hold the certificate id.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_Certificate.html#iot-Type-Certificate-certificateId
 */
#define ucdemoCERT_ID_BUFFER_LENGTH                          64

/**
 * @brief Milliseconds per second.
 */
#define ucdemoMILLISECONDS_PER_SECOND                        ( 1000U )

/**
 * @brief Milliseconds per FreeRTOS tick.
 */
#define ucdemoMILLISECONDS_PER_TICK                          ( fpdemoMILLISECONDS_PER_SECOND / configTICK_RATE_HZ )

#define ucdemoCSR_REQUEST_JSON      \
    "{"                             \
    "\"CSR\": \"%s\","              \
    "}"

/**
 * @brief Status values of the Fleet Provisioning response.
 */
typedef enum
{
    ResponseNotReceived,
    ResponseAccepted,
    ResponseRejected
} ResponseStatus_t;


/**
 * @brief Each compilation unit that consumes the NetworkContext must define it.
 * It should contain a single pointer to the type of your desired transport.
 * When using multiple transports in the same compilation unit, define this pointer as void *.
 *
 * @note Transport stacks are defined in FreeRTOS-Plus/Source/Application-Protocols/network_transport.
 */
struct NetworkContext
{
    TlsTransportParams_t * pxParams;
};

/*-----------------------------------------------------------*/
/**
 * @brief Buffer to hold the CSR subject name.
 */
static char pcCSRSubjectName[ ucdemoMAX_CSR_SUBJECT_NAME_LENGTH ] = { 0 };

/*-----------------------------------------------------------*/
/**
 * @brief Buffer to hold responses received from the AWS IoT Fleet Provisioning
 * APIs. When the MQTT publish callback receives an expected Fleet Provisioning
 * accepted payload, it copies it into this buffer.
 */
static uint8_t pucPayloadBuffer[ democonfigNETWORK_BUFFER_SIZE ];

static char pcTopicBuffer [ucdemoCRT_TOPIC_BUFFER_LENGTH] = { 0 };

/**
 * @brief The MQTT context used for MQTT operation.
 */
static MQTTContext_t xMqttContext;

/**
 * @brief The network context used for mbedTLS operation.
 */
static NetworkContext_t xNetworkContext;

/**
 * @brief The parameters for the network context using mbedTLS operation.
 */
static TlsTransportParams_t xTlsTransportParams;

/**
 * @brief Static buffer used to hold MQTT messages being sent and received.
 */
static uint8_t ucSharedBuffer[ democonfigNETWORK_BUFFER_SIZE ];

/**
 * @brief Static buffer used to hold MQTT messages being sent and received.
 */
static MQTTFixedBuffer_t xBuffer =
{
    ucSharedBuffer,
    democonfigNETWORK_BUFFER_SIZE
};

/**
 * @brief Accept topic/reject topic/publish topic
 */
static char * pcPublishTopic = NULL;
static uint16_t xPublishTopicLength;

static char * pcSubscribeTopic = NULL;
static uint16_t xSubscribeTopicLength;

static char * pcPublishMessage = NULL;
static uint16_t xPublishMessageLength;

static char * pcCert = NULL;
static char * pcConvertCert = NULL;


size_t xSubOutTopicLength = 0UL, xSubPayloadLength = 0UL, xPubOutTopicLength = 0UL, xPubPayloadLength = 0UL;
/*-----------------------------------------------------------*/

/**
 * @brief Callback to receive the incoming publish messages from the MQTT
 * broker. Sets xResponseStatus if an expected CreateCertificateFromCsr or
 * RegisterThing response is received, and copies the response into
 * responseBuffer if the response is an accepted one.
 *
 * @param[in] pPublishInfo Pointer to publish info of the incoming publish.
 * @param[in] usPacketIdentifier Packet identifier of the incoming publish.
 */
static void prvProvisioningPublishCallback( MQTTContext_t * pxMqttContext,
                                            MQTTPacketInfo_t * pxPacketInfo,
                                            MQTTDeserializedInfo_t * pxDeserializedInfo );

/**
 * @brief Subscribe to the CreateCertificateFromCsr accepted and rejected topics.
 */
static bool prvSubscribeToCsrResponseTopics( void );

/**
 * @brief Unsubscribe from the CreateCertificateFromCsr accepted and rejected topics.
 */
static bool prvUnsubscribeFromCsrResponseTopics( void );

/**
 * @brief The task used to demonstrate the FP API.
 *
 * This task uses the provided claim key and certificate files to connect to
 * AWS and use PKCS #11 to generate a new device key and certificate with a CSR.
 * The task then creates a new Thing with the Fleet Provisioning API using the
 * newly-created credentials. The task finishes by connecting to the newly-created
 * Thing to verify that it was successfully created and accessible using the key/cert.
 *
 * @param[in] pvParameters Parameters as passed at the time of task creation.
 * Not used in this example.
 */
static int prvUpdateCertificateTask( void * pvParameters );

void vStartUpdateCertificateDemo(void);

/*-----------------------------------------------------------*/

static void prvProvisioningPublishCallback( MQTTContext_t * pxMqttContext,
                                            MQTTPacketInfo_t * pxPacketInfo,
                                            MQTTDeserializedInfo_t * pxDeserializedInfo )
{
    MQTTPublishInfo_t * pxPublishInfo;

    configASSERT( pxMqttContext != NULL );
    configASSERT( pxPacketInfo != NULL );
    configASSERT( pxDeserializedInfo != NULL );

    /* Suppress the unused parameter warning when asserts are disabled in
     * build. */
    ( void ) pxMqttContext;

    /* Handle an incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pxPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        configASSERT( pxDeserializedInfo->pPublishInfo != NULL );
        pxPublishInfo = pxDeserializedInfo->pPublishInfo;

        snprintf( pcTopicBuffer, (pxPublishInfo->topicNameLength + 1), "%s", pxPublishInfo->pTopicName);
        if (0 == strcmp(pcSubscribeTopic, pcTopicBuffer))
        {
            /* Copy the payload from the MQTT library's buffer to #pucPayloadBuffer. */
            ( void ) memcpy( ( void * ) pucPayloadBuffer,
                             ( const void * ) pxPublishInfo->pPayload,
                             ( size_t ) pxPublishInfo->payloadLength );

            xSubPayloadLength = pxPublishInfo->payloadLength;
        }
        else
        {
            LogError( ( "No matches topic name" ) );
        }
    }
    else
    {
        vHandleOtherIncomingPacket( pxPacketInfo, pxDeserializedInfo->packetIdentifier );
    }
}
/*-----------------------------------------------------------*/

static bool prvSubscribeToCsrResponseTopics( void )
{
    bool xStatus;

    xStatus = xSubscribeToTopic( &xMqttContext,
                                 pcSubscribeTopic,
                                 xSubOutTopicLength );

    if( xStatus == false )
    {
        LogError( ( "Failed to subscribe to certificate topic: %.*s.",
                    xSubOutTopicLength,
                    pcSubscribeTopic ) );
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

static bool prvUnsubscribeFromCsrResponseTopics( void )
{
    bool xStatus;

    xStatus = xUnsubscribeFromTopic( &xMqttContext,
                                     pcSubscribeTopic,
                                     xSubOutTopicLength );

    if( xStatus == false )
    {
        LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                    xSubOutTopicLength,
                    pcSubscribeTopic ) );
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

/**
 * @brief Create the task that demonstrates the Update Certificate
 */
void vStartUpdateCertificateDemo()
{
    xTaskCreate( prvUpdateCertificateTask, /* Function that implements the task. */
                 "DemoTask",               /* Text name for the task - only used for debugging. */
                 democonfigDEMO_STACKSIZE, /* Size of stack (in words, not bytes) to allocate for the task. */
                 NULL,                     /* Task parameter - not used in this case. */
                 tskIDLE_PRIORITY,         /* Task priority, must be between 0 and configMAX_PRIORITIES - 1. */
                 NULL );                   /* Used to pass out a handle to the created task - not used in this case. */
}

int prvUpdateCertificateTask( void * pvParameters )
{
    int i = 0;
    bool xStatus = false;
    bool xConnectionEstablished = false;
    JSONStatus_t xjsonresult;
    /* Buffer for holding the CSR. */
    char pcCsr[ ucdemoCSR_BUFFER_LENGTH ] = { 0 };
    char pcConvertCsr[ ucdemoCSR_BUFFER_LENGTH ] = { 0 };
    size_t xCsrLength = 0;
    size_t xConvertCsrLength = 0;
    size_t xConvertCertLength = 0;
    CK_SESSION_HANDLE xP11Session;
    uint32_t ulDemoRunCount = 0U;
    CK_RV xPkcs11Ret = CKR_OK;
    char * token;
    char * jsonvalue;
    size_t jsonvalueLength;
    extern KeyValueStore_t gKeyValueStore;

    LogInfo( ( "---------Start Update Certificate Task---------\r\n" ) );

    xPublishTopicLength = ucdemoCSR_REQUEST_TOPIC_BUFFER_LENGTH;
    pcPublishTopic = pvPortMalloc(xPublishTopicLength + 1);
    xPubOutTopicLength = snprintf( pcPublishTopic, xPublishTopicLength + 1, ucdemoCSR_REQUEST_TOPIC_FORMAT, gKeyValueStore.table[KVS_CORE_THING_NAME].value);

    xSubscribeTopicLength = ucdemoCRT_TOPIC_BUFFER_LENGTH;
    pcSubscribeTopic = pvPortMalloc(xSubscribeTopicLength + 1);
    xSubOutTopicLength = snprintf( pcSubscribeTopic, xSubscribeTopicLength + 1, ucdemoCRT_TOPIC_FORMAT, gKeyValueStore.table[KVS_CORE_THING_NAME].value);

    snprintf( pcCSRSubjectName, ucdemoMAX_CSR_SUBJECT_NAME_LENGTH, "CN=%s", gKeyValueStore.table[KVS_CORE_THING_NAME].value);

    /* Silence compiler warnings about unused variables. */
    ( void ) pvParameters;

    /* Set the pParams member of the network context with desired transport. */
    xNetworkContext.pxParams = &xTlsTransportParams;

    do
    {
        /* Initialize the PKCS #11 module */
        xPkcs11Ret = xInitializePkcs11Session( &xP11Session );

        if( xPkcs11Ret != CKR_OK )
        {
            LogError( ( "Failed to initialize PKCS #11." ) );
            xStatus = false;
        }

        if ( xPkcs11Ret == CKR_OK )
        {
            xStatus = xGenerateKeyAndCsr( xP11Session,
                                          pkcs11configLABEL_UPDATE_DEVICE_PRIVATE_KEY_FOR_TLS,
                                          pkcs11configLABEL_UPDATE_DEVICE_PUBLIC_KEY_FOR_TLS,
                                          pcCsr,
                                          ucdemoCSR_BUFFER_LENGTH,
                                          &xCsrLength,
                                          pcCSRSubjectName );

            if( xStatus == false )
            {
                LogError( ( "Failed to generate Key and Certificate Signing Request." ) );
            }
        }
        else
        {
            LogError( ( "Failed to initialize PKCS #11 or get state." ) );
            xStatus = false;
        }

        if ( xStatus == true )
        {
            /**** Connect to AWS IoT Core with exist credentials *****/

            if( xStatus == true )
            {
                LogInfo( ( "Establishing MQTT session with exist certificate..." ) );
                xStatus = xEstablishMqttSession( &xMqttContext,
                                                 &xNetworkContext,
                                                 &xBuffer,
                                                 prvProvisioningPublishCallback,
                                                 pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                                 pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                                 gKeyValueStore.table[KVS_CORE_THING_NAME].value);

                if( xStatus == false )
                {
                    LogError( ( "Failed to establish MQTT session." ) );
                }
                else
                {
                    LogInfo( ( "Established connection with exist credentials." ) );
                    xConnectionEstablished = true;
                }
            }

            /**** Update Certificate from CSR ***************************/

            if( xStatus == true )
            {
                xStatus = prvSubscribeToCsrResponseTopics();
            }

            if( xStatus == true )
            {
                token = strtok( pcCsr, "\n");
                while (token != NULL)
                {
                    xConvertCsrLength += snprintf( (pcConvertCsr + xConvertCsrLength), ucdemoCSR_BUFFER_LENGTH, "%s\\n", token);
                    token = strtok(NULL, "\n");
                }
                xConvertCsrLength = 0;

                xPublishMessageLength = ucdemoCSR_BUFFER_LENGTH + 128U;
                pcPublishMessage = pvPortMalloc(xPublishMessageLength + 1);
                xPubPayloadLength = snprintf( pcPublishMessage, xPublishMessageLength + 1, ucdemoCSR_REQUEST_JSON, pcConvertCsr);
            }

            if( xStatus == true )
            {
                /* Publish the CSR to the CreateCertificatefromCsr API. */
                xStatus = xPublishToTopic( &xMqttContext,
                                           pcPublishTopic,
                                           xPubOutTopicLength,
                                           ( char * ) pcPublishMessage,
                                           xPubPayloadLength );

                if( xStatus == false )
                {
                    LogError( ( "Failed to publish to fleet provisioning topic: %.*s.",
                                pcPublishTopic,
                                xPubOutTopicLength ) );
                }
            }

            if( xStatus == true )
            {
                xjsonresult = JSON_Validate( pucPayloadBuffer, xSubPayloadLength );

                if( xjsonresult == JSONSuccess )
                {
                    xjsonresult = JSON_Search( pucPayloadBuffer, xSubPayloadLength, "certificatePem", (sizeof("certificatePem") - 1),
                                          &jsonvalue, &jsonvalueLength );

                    if ( xjsonresult == JSONSuccess )
                    {
                        pcCert = pvPortMalloc(jsonvalueLength + 1);
                        memcpy(pcCert, jsonvalue, jsonvalueLength);
                        pcConvertCert = pvPortMalloc(jsonvalueLength + 1);
                        token = strtok(pcCert, "\\");
                        while (token != NULL)
                        {
                            if (token == pcCert)
                            {
                                xConvertCertLength += snprintf( (pcConvertCert + xConvertCertLength), jsonvalueLength, "%s\n", token);
                            }
                            else
                            {
                                xConvertCertLength += snprintf( (pcConvertCert + xConvertCertLength), jsonvalueLength, "%s\n", (token + 1));
                            }

                            token = strtok(NULL, "\\");
                        }

                        xStatus = true;
                    }
                    else
                    {
                        LogError( ( "Failed to dumps certificatePem." ) );
                        xStatus = false;
                    }
                }
                else
                {
                    LogError( ( "Failed to dumps certificatePem." ) );
                    xStatus = false;
                }
            }

            if( xStatus == true )
            {
                /* Save the certificate into PKCS #11. */
                xStatus = xLoadCertificate( xP11Session,
                                            pcConvertCert,
                                            pkcs11configLABEL_UPDATE_DEVICE_CERTIFICATE_FOR_TLS,
                                            xConvertCertLength );
            }

            xConvertCertLength = 0;

            if( xStatus == true )
            {
                /* Unsubscribe from the CreateCertificateFromCsr topics. */
                xStatus = prvUnsubscribeFromCsrResponseTopics();
            }

            /**** Disconnect from AWS IoT Core ************************************/

            /* As we have completed the provisioning workflow, we disconnect from
             * the connection using the provisioning claim credentials. We will
             * establish a new MQTT connection with the newly provisioned
             * credentials. */
            if( xConnectionEstablished == true )
            {
                xDisconnectMqttSession( &xMqttContext, &xNetworkContext );
                xConnectionEstablished = false;
            }
        }

        /**** Connect to AWS IoT Core with updated certificate ************/

        if( xStatus == true )
        {
            LogInfo( ( "Establishing MQTT session with updated certificate..." ) );
            xStatus = xEstablishMqttSession( &xMqttContext,
                                             &xNetworkContext,
                                             &xBuffer,
                                             prvProvisioningPublishCallback,
                                             pkcs11configLABEL_UPDATE_DEVICE_CERTIFICATE_FOR_TLS,
                                             pkcs11configLABEL_UPDATE_DEVICE_PRIVATE_KEY_FOR_TLS,
                                             gKeyValueStore.table[KVS_CORE_THING_NAME].value );

            if( xStatus != true )
            {
                LogError( ( "Failed to establish MQTT session with provisioned "
                            "credentials. Verify on your AWS account that the "
                            "new certificate is active and has an attached IoT "
                            "Policy that allows the \"iot:Connect\" action." ) );
            }
            else
            {
                LogInfo( ( "Sucessfully established connection with provisioned credentials." ) );
                xConnectionEstablished = true;
            }
        }

        /**** Finish **********************************************************/

        if( xConnectionEstablished == true )
        {
            /* Close the connection. */
            xDisconnectMqttSession( &xMqttContext, &xNetworkContext );
            xConnectionEstablished = false;
        }

        vPortFree(pcPublishMessage);
        pcPublishMessage = NULL;

        vPortFree(pcCert);
        pcCert = NULL;

        vPortFree(pcConvertCert);
        pcConvertCert = NULL;

        vPortFree(pcPublishTopic);
        pcPublishTopic = NULL;

        vPortFree(pcSubscribeTopic);
        pcSubscribeTopic = NULL;

        /**** Retry in case of failure ****************************************/

        xPkcs11CloseSession( xP11Session );

        /* Increment the demo run count. */
        ulDemoRunCount++;

        if( xStatus == true )
        {
            LogInfo( ( "Demo iteration %d is successful.", ulDemoRunCount ) );
        }
        /* Attempt to retry a failed iteration of demo for up to #fpdemoMAX_DEMO_LOOP_COUNT times. */
        else if( ulDemoRunCount < ucdemoMAX_DEMO_LOOP_COUNT )
        {
            LogWarn( ( "Demo iteration %d failed. Retrying...", ulDemoRunCount ) );
            vTaskDelay( ucdemoDELAY_BETWEEN_DEMO_RETRY_ITERATIONS_SECONDS );
        }
        /* Failed all #fpdemoMAX_DEMO_LOOP_COUNT demo iterations. */
        else
        {
            LogError( ( "All %d demo iterations failed.", ucdemoMAX_DEMO_LOOP_COUNT ) );
            break;
        }
    } while( xStatus != true );

    /* Log demo success. */
    if( xStatus == true )
    {
        LogInfo( ( "Demo completed successfully." ) );
        LogInfo( ( "-------Update Certificate Task Finished-------\r\n" ) );
    }

    xSetMQTTAgentState( MQTT_AGENT_STATE_INITIALIZED );

    /* Delete this task. */
    LogInfo( ( "Deleting Update Certificate Demo task." ) );
    vTaskDelete( NULL );

    return ( xStatus == true ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
/*-----------------------------------------------------------*/
