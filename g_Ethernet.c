/*
 * g_ethernet_lib.c
 *
 *  Created on: 2023. 3. 7.
 *      Author: Jonghun Kim
 */

#include <g_Ethernet.h>

extern ethFrameStr          TxFrameBuffer;
extern ethFrameStr          RxFrameBuffer;
extern char                 Message[];

extern uint16_t             ServiceID;
extern uint16_t             MethodID;

uint32_t                    TxFrameSize = 0;                // Length(Size) of Transmitted Ethernet Message

pseudo_header               PsHeader;                       // TCP Pseudo Header Structure

void R_Eth_Initial_Setting()
{
    fsp_err_t err = FSP_SUCCESS;

    R_ETHER_Open(&g_ether0_ctrl, &g_ether0_cfg);

    do {
        err = R_ETHER_LinkProcess(&g_ether0_ctrl);
    } while (FSP_SUCCESS != err);

    memset(&RxFrameBuffer, 0, sizeof(ethFrameStr));

    R_ETHERC_EDMAC->EESIPR_b.TCIP = 0U;                     // Disable Transmit Interrupt Setting

    R_IOPORT_PinWrite(&g_ioport_ctrl, BSP_IO_PORT_10_PIN_08, BSP_IO_LEVEL_LOW);
}

/* To calculate the IP Checksum. */
uint16_t cal_IP_Checksum()
{
    uint16_t *ptr = NULL;
    uint32_t checksum = 0;

    for (uint8_t idx = 0; idx < ETH_IP_HEAD_SIZE / 2; idx++)
    {
        ptr = (uint16_t *)(TxFrameBuffer.ethType + ETH_HEAD_SIZE_2B + (idx * ETH_HEAD_SIZE_2B));
        checksum += (uint16_t)(*ptr << STRUCT_SHIFT_SIZE) | (uint16_t)(*ptr >> STRUCT_SHIFT_SIZE); // Consider Little Endian Format of Register
    }

    checksum = ~((checksum & FULL_MASK_16BIT) + checksum / CHECKSUM_DIV);

    return (uint16_t)checksum;
}

/* To verify whether the IP Checksum is correct. */
eth_checksum ver_IP_Checksum()
{
    uint16_t *ptr = NULL;
    uint32_t checksum = 0;

    for (uint8_t idx = 0; idx < ETH_IP_HEAD_SIZE / 2; idx++)
    {
        ptr = (uint16_t *)(RxFrameBuffer.ethType + ETH_HEAD_SIZE_2B + (idx * ETH_HEAD_SIZE_2B));
        checksum += (uint16_t)(*ptr << STRUCT_SHIFT_SIZE) | (uint16_t)(*ptr >> STRUCT_SHIFT_SIZE); // Consider Little Endian Format of Register
    }

    checksum = ~(checksum + checksum / CHECKSUM_DIV);

    if ((checksum & FULL_MASK_16BIT) == 0)
        return correct_checksum;
    else
        return wrong_checksum;
}

/* To calculate the TCP/UDP Checksum. */
uint16_t cal_TR_Checksum()
{
    uint16_t *ptr = NULL;
    uint32_t checksum = 0;

#if ETH_TCP_MODE        // If we use TCP protocol in the transport layer, this area is enabled.
    uint32_t checkLen = ETH_TCP_HEAD_SIZE + ETH_DoIP_HEAD_SIZE + strlen(Message);
#else                   // Else if we use UDP protocol in the transport layer, this area is enabled.
    uint32_t checkLen = ETH_UDP_HEAD_SIZE + ETH_SOMEIP_HEAD_SIZE + strlen(Message);
#endif

    if (checkLen % 2 != 0)
        checkLen += 1;

    for (uint32_t idx = 0; idx < checkLen / 2; idx++)
    {
        if (idx < ETH_PS_HEAD_SIZE / 2)
        {
            ptr = (uint16_t *)(PsHeader.srcIP + (idx * ETH_HEAD_SIZE_2B));
            checksum += (uint16_t)(*ptr << STRUCT_SHIFT_SIZE) | (uint16_t)(*ptr >> STRUCT_SHIFT_SIZE);
        }
        ptr = (uint16_t *)(TxFrameBuffer.srcPN + (idx * ETH_HEAD_SIZE_2B));
        checksum += (uint16_t)(*ptr << STRUCT_SHIFT_SIZE) | (uint16_t)(*ptr >> STRUCT_SHIFT_SIZE);
    }

    checksum = ~((checksum & FULL_MASK_16BIT) + checksum / CHECKSUM_DIV);

    return (uint16_t)checksum;
}

/* To verify whether the TCP/UDP Checksum is correct. */
eth_checksum ver_TR_Checksum()
{
    uint16_t *ptr = NULL;
    uint32_t checksum = 0;
    uint32_t checkLen = (uint32_t)((RxFrameBuffer.TotalLen[0] << STRUCT_SHIFT_SIZE) | RxFrameBuffer.TotalLen[1]) - ETH_IP_HEAD_SIZE;

    setPseudoHeader(RxFrameBuffer);

    if (checkLen % 2 != 0)
        checkLen += 1;

    for (uint32_t idx = 0; idx < checkLen / 2; idx++)
    {
        if (idx < ETH_PS_HEAD_SIZE / 2)
        {
            ptr = (uint16_t *)(PsHeader.srcIP + (idx * ETH_HEAD_SIZE_2B));
            checksum += (uint16_t)(*ptr << STRUCT_SHIFT_SIZE) | (uint16_t)(*ptr >> STRUCT_SHIFT_SIZE);
        }
        ptr = (uint16_t *)(RxFrameBuffer.srcPN + (idx * ETH_HEAD_SIZE_2B));
        checksum += (uint16_t)(*ptr << STRUCT_SHIFT_SIZE) | (uint16_t)(*ptr >> STRUCT_SHIFT_SIZE);
    }

    checksum = ~(checksum + checksum / CHECKSUM_DIV);

    if ((checksum & FULL_MASK_16BIT) == 0)
        return correct_checksum;
    else
        return wrong_checksum;
}

void setPseudoHeader(ethFrameStr DataStr)
{
    memcpy(&PsHeader.srcIP[0], &DataStr.srcIP[0], ETH_HEAD_SIZE_4B);
    memcpy(&PsHeader.dstIP[0], &DataStr.dstIP[0], ETH_HEAD_SIZE_4B);

    memset(&PsHeader.Reserved, 0, ETH_HEAD_SIZE_1B);
    memcpy(&PsHeader.Protocol, &DataStr.Protocol, ETH_HEAD_SIZE_1B);

    PsHeader.TotalLen[0] = DataStr.TotalLen[0];
    PsHeader.TotalLen[1] = DataStr.TotalLen[1] - ETH_IP_HEAD_SIZE;        // Only Calculate TCP Header + Data Section
}

void setLayer2(uint8_t *dMAC, uint8_t *sMAC)
{
    // Ethernet Frame Destination & Source MAC Address Setting //
    memcpy(&TxFrameBuffer.dstMAC[0], dMAC, ETH_HEAD_SIZE_6B);
    memcpy(&TxFrameBuffer.srcMAC[0], sMAC, ETH_HEAD_SIZE_6B);

#if ETH_VLAN_MODE       // If we use VLAN Security Mode in the data-link layer, this area is enabled.
    // Ethernet Frame VLAN Type Setting: 0x8100 //
    TxFrameBuffer.VLANType[0] = (uint8_t)(ETH_VLAN_TYPE >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.VLANType[1] = (uint8_t)(ETH_VLAN_TYPE & FULL_MASK_8BIT);

    // Ethernet Frame VLAN Security Setting //
    TxFrameBuffer.PRI = VLAN_PRI;
    TxFrameBuffer.DEI = VLAN_DEI;
    TxFrameBuffer.IDH = VLAN_ID >> STRUCT_SHIFT_SIZE;
    TxFrameBuffer.IDL = VLAN_ID & FULL_MASK_8BIT;
#endif

    // Ethernet Frame Type & Length Setting: IPv4 [0x0800] //
    TxFrameBuffer.ethType[0] = (uint8_t)(ETH_IPv4_TYPE >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.ethType[1] = (uint8_t)(ETH_IPv4_TYPE & FULL_MASK_8BIT);
}

void setLayer3(uint8_t *dIP, uint8_t *sIP)
{
    // Ethernet Packet IP Header Setting //
    TxFrameBuffer.IPV = ETH_IPV_IPv4;
    TxFrameBuffer.IHL = ETH_IHL_5;
    TxFrameBuffer.DSCP = ETH_DSCP_INIT;
    TxFrameBuffer.ECN = ETH_ECN_INIT;

#if ETH_TCP_MODE        // If we use TCP protocol in the transport layer, this area is enabled.
    uint16_t TotalLen = (uint16_t)(ETH_IP_HEAD_SIZE + ETH_TCP_HEAD_SIZE + ETH_DoIP_HEAD_SIZE + strlen(Message));
#else                   // Else if we use UDP protocol in the transport layer, this area is enabled.
    uint16_t TotalLen = (uint16_t)(ETH_IP_HEAD_SIZE + ETH_UDP_HEAD_SIZE + ETH_SOMEIP_HEAD_SIZE + strlen(Message));
#endif

    TxFrameBuffer.TotalLen[0] = (uint8_t)(TotalLen >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.TotalLen[1] = (uint8_t)(TotalLen & FULL_MASK_8BIT);

    TxFrameBuffer.GroupID[0] = ETH_IP_GID >> STRUCT_SHIFT_SIZE;
    TxFrameBuffer.GroupID[1] = ETH_IP_GID & FULL_MASK_8BIT;

    TxFrameBuffer.fragInfo[0] = ETH_NonFrag | (ETH_FragOffset >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.fragInfo[1] = ETH_FragOffset & FULL_MASK_8BIT;

    TxFrameBuffer.TTL = ETH_TTL_INIT;

#if ETH_TCP_MODE        // If we use TCP protocol in the transport layer, this area is enabled.
    TxFrameBuffer.Protocol = ETH_TCP_PROT;
#else                   // Else if we use UDP protocol in the transport layer, this area is enabled.
    TxFrameBuffer.Protocol = ETH_UDP_PROT;
#endif

    // Ethernet Packet Destination & Source IP Address Setting //
    memcpy(&TxFrameBuffer.dstIP[0], dIP, ETH_HEAD_SIZE_4B);
    memcpy(&TxFrameBuffer.srcIP[0], sIP, ETH_HEAD_SIZE_4B);
}

void setLayer4(uint32_t PN, uint16_t wSize, uint8_t flag)
{
    TxFrameBuffer.srcPN[0] = (uint8_t)(PN >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.srcPN[1] = PN & FULL_MASK_8BIT;

    TxFrameBuffer.dstPN[0] = (uint8_t)(PN >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.dstPN[1] = PN & FULL_MASK_8BIT;

#if ETH_TCP_MODE    // If we use TCP protocol in the transport layer, this area is enabled.
    memset(&TxFrameBuffer.SeqNum[0], 0, ETH_HEAD_SIZE_4B);
    memset(&TxFrameBuffer.AckNum[0], 0, ETH_HEAD_SIZE_4B);

    TxFrameBuffer.Offset = ETH_Offset_5;
    TxFrameBuffer.Reserved = 0b0000;

    memcpy(&TxFrameBuffer.WindowSize[0] - 1, &flag, ETH_HEAD_SIZE_1B);

    TxFrameBuffer.WindowSize[0] = (uint8_t)(wSize >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.WindowSize[1] = (uint8_t)(wSize & FULL_MASK_8BIT);

    memset(&TxFrameBuffer.UrgentPtr[0], 0, ETH_HEAD_SIZE_2B);
#else               // Else if we use UDP protocol in the transport layer, this area is enabled.
    FSP_PARAMETER_NOT_USED(wSize);
    FSP_PARAMETER_NOT_USED(flag);
    uint16_t length = (uint16_t)(ETH_UDP_HEAD_SIZE + ETH_SOMEIP_HEAD_SIZE + strlen(Message));

    TxFrameBuffer.UDPLen[0] = (uint8_t)(length >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.UDPLen[1] = (uint8_t)(length & FULL_MASK_8BIT);
#endif

    /* OSI 5th [Session] Layer: DoIP or SOME/IP */
    setLayer5();

    /* OSI 7th [Application] Layer: Message */
    memcpy(&TxFrameBuffer.payload[0], Message, strlen(Message));
}

void setLayer5()
{
#if ETH_SOMEIP_MODE
    TxFrameBuffer.serviceID[0] = (uint8_t)(ServiceID >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.serviceID[1] = (uint8_t)(ServiceID & FULL_MASK_8BIT);

    TxFrameBuffer.methodID[0] = (uint8_t)(MethodID >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.methodID[1] = (uint8_t)(MethodID & FULL_MASK_8BIT);

    uint32_t length = ETH_SOMEIP_HEAD_SIZE - ETH_HEAD_SIZE_4B * 2 + strlen(Message);
    TxFrameBuffer.length[0] = (uint8_t)(length >> STRUCT_SHIFT_SIZE * 3);
    TxFrameBuffer.length[1] = (uint8_t)(length >> STRUCT_SHIFT_SIZE * 2);
    TxFrameBuffer.length[2] = (uint8_t)(length >> STRUCT_SHIFT_SIZE * 1);
    TxFrameBuffer.length[3] = (uint8_t)(length & FULL_MASK_8BIT);

    TxFrameBuffer.clientPref = 0x00;
    TxFrameBuffer.clientID = 0x00;
    TxFrameBuffer.sessionID[0] = 0x00;
    TxFrameBuffer.sessionID[1] = 0x00;

    TxFrameBuffer.someipVer = ETH_SOMEIP_PROT_VER;
    TxFrameBuffer.ifaceVer = ETH_SOMEIP_IFACE_VER;
    TxFrameBuffer.msgType = SOMEIP_REQUEST;
    TxFrameBuffer.returncode = 0;
#else
    // Reserved DoIP Area
#endif
}

//////////////////////////////////////////////////////
/// Main Function of Entire Ethernet Frame Setting ///
//////////////////////////////////////////////////////
void setEthFrame(uint8_t *dMAC, uint8_t *sMAC, uint8_t *dIP, uint8_t *sIP, uint32_t PN, uint8_t flag)
{
    uint16_t wSize = 3000; // TCP Window Size

    /* Frame Structure Buffer Initialization */
    memset(&TxFrameBuffer, 0, sizeof(TxFrameBuffer));
    memset(&PsHeader, 0, sizeof(PsHeader));

    /* OSI 2nd [Data-link] Layer: Ethernet MAC */
    setLayer2(dMAC, sMAC);

    /* OSI 3rd [Network] Layer: IPv4 */
    setLayer3(dIP, sIP);
    uint16_t IPchecksum = cal_IP_Checksum();
    TxFrameBuffer.ICS[0] = (uint8_t)(IPchecksum >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.ICS[1] = (uint8_t)(IPchecksum & FULL_MASK_8BIT);

    /* OSI 4th [Transport] Layer: TCP or UDP */
    setLayer4(PN, wSize, flag);
    setPseudoHeader(TxFrameBuffer);

#if ETH_TCP_MODE    // If we use TCP protocol in the transport layer, this area is enabled.
    uint16_t TCPchecksum = cal_TR_Checksum();
    TxFrameBuffer.TCS[0] = (uint8_t)(TCPchecksum >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.TCS[1] = (uint8_t)(TCPchecksum & FULL_MASK_8BIT);
#else               // Else if we use UDP protocol in the transport layer, this area is enabled.
    uint16_t UDPchecksum = cal_TR_Checksum();
    TxFrameBuffer.UCS[0] = (uint8_t)(UDPchecksum >> STRUCT_SHIFT_SIZE);
    TxFrameBuffer.UCS[1] = (uint8_t)(UDPchecksum & FULL_MASK_8BIT);
#endif
}
