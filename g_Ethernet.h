/*
 * g_ethernet_lib.h
 *
 *  Created on: 2023. 3. 7.
 *      Author: Jonghun Kim
 */

#include <hal_data.h>

#ifndef G_ETHERNET_LIB_H_
#define G_ETHERNET_LIB_H_

//////////////////////// USER DEFINITION AREA (Ethernet Parameters) ////////////////////////

////////// Programmable Mode Setting //////////
#define ETH_VLAN_MODE                   false
#define ETH_IP_OPTIONAL                 false
#define ETH_TCP_MODE                    false
#define ETH_TCP_OPTIONAL                false
#define ETH_SOMEIP_MODE                 true
#define ETH_SOMEIP_OPTIONAL             false
///////////////////////////////////////////////

#define ETH_MTU_SIZE                    1500                    // Ethernet II Frame Maximum Transmission Unit Size

#define ETH_IP_HEAD_SIZE                20                      // Initial Setting (No use IP Header Options)
#define ETH_TCP_HEAD_SIZE               20                      // Initial Setting (No use TCP Header Options)
#define ETH_UDP_HEAD_SIZE               8                       // Fixed Size      (UDP don't have options)
#define ETH_SOMEIP_HEAD_SIZE            16                      // Initial Setting (No use ECE Protection Options)
#define ETH_DoIP_HEAD_SIZE              8                       // Initial Setting (No Additional Options)

#define ETH_DSCP_INIT                   0b000000                // Ethernet IP DSCP Initial Setting
#define ETH_ECN_INIT                    0b00                    // Ethernet IP ECN Initial Setting
#define ETH_IP_GID                      0x0001                  // Ethernet IP Group ID Setting
#define ETH_TTL_INIT                    0x40                    // Ethernet IP Time-to-live Initial Setting (64 hop counts)

// Please check this site: "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
#define PN_DoIP                         13400U                  // Ethernet Port Number: DoIP (13400, fixed value)
#define PN_SOMEIP                       30509U                  // Ethernet Port Number: SOME/IP (User Definable)

#define ETH_SOMEIP_PROT_VER             0x01                    // Ethernet SOME/IP Protocol Version
#define ETH_SOMEIP_IFACE_VER            0x01                    // Ethernet SOME/IP Service Interface Version

////////////////////////////////////////////////////////////////////////////////////////////





//////////////////////// Static Constant AREA (Ethernet Parameters) ////////////////////////

#define STRUCT_SHIFT_SIZE               8
#define FULL_MASK_8BIT                  0xFF
#define FULL_MASK_16BIT                 0xFFFF
#define FULL_MASK_32BIT                 0xFFFFFFFF

#define ETH_HEAD_SIZE_1B                1
#define ETH_HEAD_SIZE_2B                2
#define ETH_HEAD_SIZE_4B                4
#define ETH_HEAD_SIZE_6B                6

#define ETH_TYPE_SIZE                   2
#define ETH_MAC_ADDR_SIZE               6

#if ETH_VLAN_MODE                       // If we use VLAN Security Mode in the data-link layer, this area is enabled.
#define VLAN_PRI                        0b001                   // [15:13] VLAN Priority Code Point (3-bit)
#define VLAN_DEI                        0b1                     // [12:12] VLAN Drop Eligible Indicator (1-bit)
#define VLAN_ID                         0b000000110000          // [11: 0] VLAN Identifier (12-bit)

#define ETH_VLAN_TYPE                   0x8100

#define ETH_MAC_HEAD_SIZE               (ETH_MAC_ADDR_SIZE * 2 + ETH_TYPE_SIZE * 3)
#else
#define ETH_MAC_HEAD_SIZE               (ETH_MAC_ADDR_SIZE * 2 + ETH_TYPE_SIZE)
#endif

#define ETH_PS_HEAD_SIZE                12                      // TCP Pseudo Header Size

#define ETH_IPv4_TYPE                   0x0800

#define ETH_IPV_IPv4                    0b0100
#define ETH_IPV_IPv6                    0b0110

#define ETH_IHL_5                       0b0101
#define ETH_IHL_6                       0b0110
#define ETH_IHL_7                       0b0111
#define ETH_IHL_8                       0b1000

#define ETH_NonFrag                     0x40
#define ETH_MulFrag                     0x20
#define ETH_FragOffset                  0x0000

#define ETH_ICMP_PROT                   0x01
#define ETH_IGMP_PROT                   0x02
#define ETH_TCP_PROT                    0x06
#define ETH_UDP_PROT                    0x11

#define CHECKSUM_DIV                    65536

#define Init_SeqNum                     0

#define ETH_Offset_5                    0b0101
#define ETH_Offset_6                    0b0110
#define ETH_Offset_7                    0b0111
#define ETH_Offset_8                    0b1000
#define ETH_Offset_9                    0b1001
#define ETH_Offset_A                    0b1010
#define ETH_Offset_B                    0b1011
#define ETH_Offset_C                    0b1100
#define ETH_Offset_D                    0b1101
#define ETH_Offset_E                    0b1110
#define ETH_Offset_F                    0b1111

#define ETH_CWR_MASK                    0b10000000
#define ETH_ECE_MASK                    0b01000000
#define ETH_URG_MASK                    0b00100000
#define ETH_ACK_MASK                    0b00010000
#define ETH_PSH_MASK                    0b00001000
#define ETH_RST_MASK                    0b00000100
#define ETH_SYN_MASK                    0b00000010
#define ETH_FIN_MASK                    0b00000001

#define SOMEIP_REQUEST                  0x00
#define SOMEIP_NO_RETURN                0x01
#define SOMEIP_NOTIFICATION             0x02
#define SOMEIP_RESPONSE                 0x80
#define SOMEIP_ERROR                    0x81
#define SOMEIP_TP_REQUEST               0x20
#define SOMEIP_TP_NO_RETURN             0x21
#define SOMEIP_TP_NOTIFICATION          0x22
#define SOMEIP_TP_RESPONSE              0xA0
#define SOMEIP_TP_ERROR                 0xA1

#define RCODE_E_OK                      0x00
#define RCODE_E_NOT_OK                  0x01
#define RCODE_E_UNKNOWN_SERVICE         0x02
#define RCODE_E_UNKNOWN_METHOD          0x03
#define RCODE_E_NOT_READY               0x04
#define RCODE_E_NOT_REACHABLE           0x05
#define RCODE_E_TIMEOUT                 0x06
#define RCODE_E_WRONG_PROTOCOL_VERSION  0x07
#define RCODE_E_WRONG_INTERFACE_VERSION 0x08
#define RCODE_E_MALFORMET_MESSAGE       0x09
#define RCODE_E_WRONG_MESSAGE_TYPE      0x0A
#define RCODE_E_E2E_REPEATED            0x0B
#define RCODE_E_E2E_WRONG_SEQUENCE      0x0C
#define RCODE_E_E2E                     0x0D
#define RCODE_E_E2E_NOT_AVAILABLE       0x0E
#define RCODE_E_E2E_NO_NEW_DATA         0x0F
#define RCODE_RESERVED                  0x10

////////////////////////////////////////////////////////////////////////////////////////////

typedef enum    _eth_direction          eth_direction;
typedef enum    _eth_checksum           eth_checksum;
typedef struct  _ethFrameStr            ethFrameStr;

void R_Eth_Initial_Setting();
uint16_t cal_IP_Checksum();
eth_checksum ver_IP_Checksum();
uint16_t cal_TR_Checksum();
eth_checksum ver_TR_Checksum();
void setLayer2(uint8_t *dMAC, uint8_t *sMAC);
void setLayer3(uint8_t *dIP, uint8_t *sIP);
void setLayer4(uint32_t PN, uint16_t wSize, uint8_t flag);
void setLayer5();
void setPseudoHeader(ethFrameStr DataStr);
void setEthFrame(uint8_t *dMAC, uint8_t *sMAC, uint8_t *dIP, uint8_t *sIP, uint32_t PN, uint8_t flag);

////////////////////////////////////////////////////////////////////////////////////////////

typedef enum _eth_checksum{
    correct_checksum = 0,
    wrong_checksum
} eth_checksum;

typedef enum _eth_direction{
    transmit = 0,
    receive
} eth_direction;

typedef struct _pseudo_header {
    uint8_t                 srcIP[ETH_HEAD_SIZE_4B];
    uint8_t                 dstIP[ETH_HEAD_SIZE_4B];
    uint8_t                 Reserved;
    uint8_t                 Protocol;
    uint8_t                 TotalLen[ETH_HEAD_SIZE_2B];
} pseudo_header;

typedef struct _ethFrameStr{
    ///////////////////////////////////////////////////////////////////
    /** Support Data-link Layer (OSI-2nd-Layer) (Ethernet II Frame) **/
    ///////////////////////////////////////////////////////////////////

    uint8_t                 dstMAC[ETH_HEAD_SIZE_6B];   // Destination MAC Address (6bytes)
    uint8_t                 srcMAC[ETH_HEAD_SIZE_6B];   // Source MAC Address (6bytes)

#if ETH_VLAN_MODE           // If we use VLAN Security Mode in the data-link layer, this area is enabled.
    uint8_t                 VLANType[ETH_HEAD_SIZE_2B]; // VLAN Type: 0x8100 (2bytes)

    uint8_t                 IDH : 4;                    // VLAN Tag ID High
    uint8_t                 DEI : 1;                    // VLAN Tag DEI
    uint8_t                 PRI : 3;                    // VLAN Tag Priority
    uint8_t                 IDL : 8;                    // VLAN Tag ID Low
#endif

    uint8_t                 ethType[ETH_HEAD_SIZE_2B];  // EtherType (2bytes)

    ///////////////////////////////////////////////////////////////////////////
    /** Support Network Layer (OSI-3rd-Layer) (Internet Protocol Version 4) **/
    ///////////////////////////////////////////////////////////////////////////

    uint8_t                 IHL : 4;                    // Internet Protocol Header Length (Unit: Word)
    uint8_t                 IPV : 4;                    // Internet Protocol Version (4 or 6)
    uint8_t                 ECN : 2;                    // Explicit Congestion Notification
    uint8_t                 DSCP : 6;                   // Differentiated Services Code Point

    uint8_t                 TotalLen[ETH_HEAD_SIZE_2B]; // Total Packet Size (Unit: Byte)
    uint8_t                 GroupID[ETH_HEAD_SIZE_2B];  // Fragmentation Group Identification
    uint8_t                 fragInfo[ETH_HEAD_SIZE_2B]; // Flags and Fragment Offset
    uint8_t                 TTL;                        // Time-to-Live of Packet (Prevent routing-loop)
    uint8_t                 Protocol;                   // Upper Layer Protocol Type (Example: ICMP[0x01] / IGMP[0x02] / TCP[0x06] / UDP[0x11])
    uint8_t                 ICS[ETH_HEAD_SIZE_2B];      // IP Header Checksum Value

    uint8_t                 srcIP[ETH_HEAD_SIZE_4B];    // Source IP Address (4bytes)
    uint8_t                 dstIP[ETH_HEAD_SIZE_4B];    // Destination IP Address (4bytes)

#if ETH_IP_OPTIONAL
    uint8_t                 ipOptions;                  // IP Header Options (if IHL > 5)
#endif

    ///////////////////////////////////////////////////////////
    /** Support Transport Layer (OSI-4th-Layer) (TCP / UDP) **/
    ///////////////////////////////////////////////////////////

#if ETH_TCP_MODE            // If we use TCP protocol in the transport layer, this area is enabled.
    //////////////////////////////////////////////////
    /// TCP[Transmission Control Protocol] Section ///
    //////////////////////////////////////////////////

    uint8_t                 srcPN[ETH_HEAD_SIZE_2B];        // TCP Source Port Number (= Sender's Application Service Number)               (2bytes)
    uint8_t                 dstPN[ETH_HEAD_SIZE_2B];        // TCP Destination Port Number (= Receiver's Application Service Number)        (2bytes)
    uint8_t                 SeqNum[ETH_HEAD_SIZE_4B];       // TCP Segment Sequence Number                                                  (4bytes)
    uint8_t                 AckNum[ETH_HEAD_SIZE_4B];       // TCP Acknowledgment Number                                                    (4bytes)

    uint8_t                 Reserved : 4;                   // TCP Header Reserved Area to use future                                       (4bits)
    uint8_t                 Offset : 4;                     // TCP Header Size (Initial: 5 Words, Maximum: 15 Words)                        (4bits)

    /* TCP Header Flag Area (Total 8bits) */
    uint8_t                 FIN : 1;                        // TCP Flag: Finish Number                                                      (1bit)
    uint8_t                 SYN : 1;                        // TCP Flag: Synchronize Sequence Number                                        (1bit)
    uint8_t                 RST : 1;                        // TCP Flag: Reset the Connection                                               (1bit)
    uint8_t                 PSH : 1;                        // TCP Flag: Push Function Setting                                              (1bit)
    uint8_t                 ACK : 1;                        // TCP Flag: Acknowledgment Setting Field                                       (1bit)
    uint8_t                 URG : 1;                        // TCP Flag: Urgent Data Area Enable Setting Field                              (1bit)
    uint8_t                 ECE : 1;                        // TCP Flag: ECN-Echo (Network Congestion Option)                               (1bit)
    uint8_t                 CWR : 1;                        // TCP Flag: Congestion Window Reduced Field                                    (1bit)

    uint8_t                 WindowSize[ETH_HEAD_SIZE_2B];   // TCP Window Maximum Size (General: 65,535 Bytes)                              (2bytes)
    uint8_t                 TCS[ETH_HEAD_SIZE_2B];          // TCP Header, Payload, and IP Pseudo-Header Checksum Value                     (2bytes)

    uint8_t                 UrgentPtr[ETH_HEAD_SIZE_2B];    // TCP Urgent Data Area Pointer(Last Offset)                                    (2bytes)

    uint8_t                 payload[ETH_MTU_SIZE - ETH_IP_HEAD_SIZE - ETH_TCP_HEAD_SIZE];                                                // (1460bytes)

#if ETH_TCP_OPTIONAL
    uint8_t                 tcpOptions;                     // TCP Header Options (if Offset > 5)
#endif

#else                       // Else if we use UDP protocol in the transport layer, this area is enabled.
    ///////////////////////////////////////////
    /// UDP[User Datagram Protocol] Section ///
    ///////////////////////////////////////////

    uint8_t                 srcPN[ETH_HEAD_SIZE_2B];        // UDP Source Port Number (= Sender's Application Service Number)               (2bytes)
    uint8_t                 dstPN[ETH_HEAD_SIZE_2B];        // UDP Destination Port Number (= Receiver's Application Service Number)        (2bytes)

    uint8_t                 UDPLen[ETH_HEAD_SIZE_2B];       // "UDP Header + UDP Data Stream" Total Size                                    (2bytes)
    uint8_t                 UCS[ETH_HEAD_SIZE_2B];          // UDP Header, Payload Checksum Value (Optional in IPv4)                        (2bytes)
#endif
    /////////////////////////////////////////////////////////////
    /** Support Session Layer (OSI-5th-Layer) (SOMEIP / DoIP) **/
    /////////////////////////////////////////////////////////////

#if ETH_SOMEIP_MODE
    /////////////////////////////////////////////////////////////////////
    /// SOME/IP[Scalable service-Oriented MiddlewarE over IP] Section ///
    /////////////////////////////////////////////////////////////////////

    uint8_t                 serviceID[ETH_HEAD_SIZE_2B];    // SOME/IP Service ID (distinguish up to 2^16 services)
    uint8_t                 methodID[ETH_HEAD_SIZE_2B];     // SOME/IP Method ID (distinguish up to 2^16 service elements)

    uint8_t                 length[ETH_HEAD_SIZE_4B];       // SOME/IP Length covered from Request/Client ID until the end of the SOME/IP message

    uint8_t                 clientPref;                     // SOME/IP Configurable Client Prefix
    uint8_t                 clientID;                       // SOME/IP Unique Client Identifier
    uint8_t                 sessionID[ETH_HEAD_SIZE_2B];    // SOME/IP Unique Sequential Message Identifier

    uint8_t                 someipVer;                      // SOME/IP Header Format Version (Not Upper Layer Protocol Version)
    uint8_t                 ifaceVer;                       // SOME/IP Service Interface Version
    uint8_t                 msgType;                        // SOME/IP Message Type
    uint8_t                 returncode;                     // SOME/IP Response Return Code

#if ETH_SOMEIP_OPTIONAL
    uint8_t                 E2Eheader;
#endif

#else
    ///////////////////////////////////////////////////////
    /// DoIP[Diagnostic over Internet Protocol] Section ///
    ///////////////////////////////////////////////////////

    uint8_t                 doipVer;                        // DoIP Header Format Version (Not Upper Layer Protocol Version)
    uint8_t                 inverseVer;                     // DoIP Inverse Header Format Version

    uint8_t                 payloadType[ETH_HEAD_SIZE_2B];  // DoIP Payload (Application Message) Type
    uint8_t                 payloadLen[ETH_HEAD_SIZE_4B];   // DoIP Payload Message Length (based UDS Protocol)
#endif

    /////////////////////////////////////
    /// Application (Message) Section ///
    /////////////////////////////////////

#if ETH_SOMEIP_MODE
    uint8_t                 payload[ETH_MTU_SIZE - ETH_IP_HEAD_SIZE - ETH_UDP_HEAD_SIZE - ETH_SOMEIP_HEAD_SIZE]; // Total 1472bytes
#else
    uint8_t                 payload[ETH_MTU_SIZE - ETH_IP_HEAD_SIZE - ETH_TCP_HEAD_SIZE - ETH_DoIP_HEAD_SIZE]; // Total 1472bytes
#endif
} ethFrameStr;

#endif /* G_ETHERNET_LIB_H_ */
