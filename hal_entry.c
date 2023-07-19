#include <g_DeviceDriver.h>
#include <g_Ethernet.h>

FSP_CPP_HEADER
void R_BSP_WarmStart(bsp_warm_start_event_t event);
FSP_CPP_FOOTER

ethFrameStr  TxFrameBuffer;                 // Set Transmit Ethernet Message (VLAN Security Assist)
ethFrameStr  RxFrameBuffer;                 // Get Receive Ethernet Message (VLAN Security Assist)
uint32_t     RxFrameSize = 0;               // Length(Size) of Received Ethernet Message

///////////////////////////////// Ethernet Frame Parameters (User Definable) /////////////////////////////////

uint8_t      DstMAC[ETH_HEAD_SIZE_6B]    = {0x00, 0xE0, 0x4C, 0x68, 0x08, 0x6F};         // Destination MAC Address
uint8_t      SrcMAC[ETH_HEAD_SIZE_6B]    = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};         // Source MAC Address
uint8_t      SrcIP[ETH_HEAD_SIZE_4B]     = {192, 168, 2, 0};                             // Source IP Address
uint8_t      DstIP[ETH_HEAD_SIZE_4B]     = {192, 168, 1, 0};                             // Destination IP Address
uint8_t      flag                        = ETH_SYN_MASK;                                 // TCP Flag
uint16_t     ServiceID                   = 0x1234;                                       // SOME/IP Service ID
uint16_t     MethodID                    = 0x0000;                                       // SOME/IP Method ID

char         Message[] = "Automation Lab!";                                              // Payload Raw Message

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

void hal_entry(void)
{
    HW_Initial_Setting();
    setEthFrame(DstMAC, SrcMAC, DstIP, SrcIP, PN_SOMEIP, flag);  // Set the Transmission Ethernet Frame Structure

    while(true);
}

void R_IRQ_Callback(external_irq_callback_args_t *p_args)
{
#if ETH_TCP_MODE        // If we use TCP protocol in the transport layer, this area is enabled.
    uint32_t totalLen = ETH_MAC_HEAD_SIZE + ETH_IP_HEAD_SIZE + ETH_TCP_HEAD_SIZE + ETH_DoIP_HEAD_SIZE + strlen(Message);
#else                   // Else if we use UDP protocol in the transport layer, this area is enabled.
    uint32_t totalLen = ETH_MAC_HEAD_SIZE + ETH_IP_HEAD_SIZE + ETH_UDP_HEAD_SIZE + ETH_SOMEIP_HEAD_SIZE + strlen(Message);
#endif
    switch(p_args->channel)
    {
        /* Ethernet Frame Transmission (support MAC, IPv4, TCP/UDP, SOME/IP) */
        case EXTERNAL_INTERRUPT_11:
            setEthFrame(DstMAC, SrcMAC, DstIP, SrcIP, PN_SOMEIP, flag);  // Set the Transmission Ethernet Frame Structure
            R_ETHER_Write(&g_ether0_ctrl, &TxFrameBuffer, totalLen);
            break;
        case EXTERNAL_INTERRUPT_12:
            break;
        case EXTERNAL_INTERRUPT_13:
            break;
        case EXTERNAL_INTERRUPT_14:
            break;
    }
}

/* Receive Ethernet Frame from PC */
void R_Eth_Callback(ether_callback_args_t *p_args)
{
    R_IOPORT_PinWrite(&g_ioport_ctrl, BSP_IO_PORT_10_PIN_09, BSP_IO_LEVEL_HIGH);

    switch(p_args->event)
    {
        case ETHER_EVENT_INTERRUPT:
            // You must set "RACT" in the Receive Descriptor to 1 after occur Ethernet Handler.
            // If you use "R_ETHER_Read" HAL Function, Receive Descriptor is automatically set.
            R_ETHER_Read(&g_ether0_ctrl, &RxFrameBuffer, &RxFrameSize);

            if (ver_IP_Checksum())
                if (ver_TR_Checksum())
                    return;

            R_IOPORT_PinWrite(&g_ioport_ctrl, BSP_IO_PORT_10_PIN_09, BSP_IO_LEVEL_LOW);
            break;
        default:
            break;
    }
}

/*******************************************************************************************************************//**
 * This function is called at various points during the startup process.  This implementation uses the event that is
 * called right before main() to set up the pins.
 *
 * @param[in]  event    Where at in the start up process the code is currently at
 **********************************************************************************************************************/
void R_BSP_WarmStart(bsp_warm_start_event_t event)
{
    if (BSP_WARM_START_RESET == event)
    {
#if BSP_FEATURE_FLASH_LP_VERSION != 0

        /* Enable reading from data flash. */
        R_FACI_LP->DFLCTL = 1U;

        /* Would normally have to wait tDSTOP(6us) for data flash recovery. Placing the enable here, before clock and
         * C runtime initialization, should negate the need for a delay since the initialization will typically take more than 6us. */
#endif
    }

    if (BSP_WARM_START_POST_C == event)
    {
        /* C runtime environment and system clocks are setup. */

        /* Configure pins. */
        R_IOPORT_Open (&g_ioport_ctrl, g_ioport.p_cfg);
    }
}

#if BSP_TZ_SECURE_BUILD

BSP_CMSE_NONSECURE_ENTRY void template_nonsecure_callable ();

/* Trustzone Secure Projects require at least one nonsecure callable function in order to build (Remove this if it is not required to build). */
BSP_CMSE_NONSECURE_ENTRY void template_nonsecure_callable ()
{

}
#endif
