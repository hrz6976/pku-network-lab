// Simplified TCP Transmission
// 12f23eddde <rzhe@pku.edu.cn> - May 10 2021
#include "sysInclude.h"

#include <cstdlib>
#include <cstring>
#include <vector>
#include <iostream>

// make idea happy
#include <netinet/in.h>

using namespace std;

extern void tcp_DiscardPkt(char * pBuffer, int type);
extern void tcp_sendIpPkt(unsigned char* pData, uint16 len, unsigned int srcAddr, unsigned int dstAddr, uint8 ttl);
extern int waitIpPacket(char *pBuffer, int timeout);
extern void tcp_sendReport(int type);
extern UINT32 getIpv4Address( );
extern UINT32 getServerIpv4Address( );

#define MAX_OPEN_FD 100

/*
struct sockaddr_in {
    short   sin_family;
    u_short sin_port;
    struct  in_addr sin_addr;
    char    sin_zero[8];
};
*/

/*typedef struct tcpHead{
	UINT16 srcPort;
	UINT16 destPort;
	UINT32 seqNo;
	UINT32 ackNo;
	UINT8  headLen;
	UINT8  flag;
	UINT16 windowsize;
	UINT16 checksum;
	UINT16 urgentPointer;
	char pData[1];
};
 */

// safely convert a raw tcpbuffer to something we can read
struct TCPHeaderInfo {
    uint16_t srcPort, destPort, windowsize, checksumNet, urgentPointer;
    uint32_t seqNo, ackNo;
    uint8_t headLen;
    bool is_urg, is_ack, is_psh, is_rst, is_syn, is_fin;

    TCPHeaderInfo(char* pBuffer) {
        struct tcpHead head;
        memcpy(pBuffer, &head, sizeof(head)); // copy to buffer
        srcPort = ntohs(head.srcPort);
        destPort = ntohs(head.destPort);
        seqNo = ntohl(head.seqNo);
        ackNo = ntohl(head.ackNo);
        headLen = (head.headLen) >> 4;
        is_urg = (head.flag >> 5) & 0x1;
        is_ack = (head.flag >> 4) & 0x1;
        is_psh = (head.flag >> 3) & 0x1;
        is_rst = (head.flag >> 2) & 0x1;
        is_syn = (head.flag >> 1) & 0x1;
        is_fin = (head.flag) & 0x1;
        windowsize = ntohs(head.windowsize);
        checksumNet = head.checksum; // checksum in n-order
        urgentPointer = ntohs(head.urgentPointer);
        delete &head;
    }

    void print() {
        printf("seq=%d ack=%d len=%d ws=%d |", seqNo, ackNo, headLen, windowsize);
        if(is_urg) printf("URG ");
        if(is_ack) printf("ACK ");
        if(is_psh) printf("PSH ");
        if(is_rst) printf("RST ");
        if(is_syn) printf("SYN ");
        if(is_fin) printf("FIN ");
        printf("\n");
    }
};

enum TCPStatus {
    CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT1, FIN_WAIT2, TIME_WAIT
};

struct TCBEntry {
    uint32_t srcAddr, destAddr;
    uint16_t srcPort, destPort;
    uint32_t window, nextSend, nextRecv;
    uint16_t status;
};

TCBEntry TCBTable[MAX_OPEN_FD];

int getTcbByIp(uint32_t srcAddr, uint16_t srcPort, uint32_t destAddr, uint32_t destPort){
    for(int i = 0; i < MAX_OPEN_FD; i++){
        TCBEntry* it = &TCBTable[i];
        if(it->srcAddr==srcAddr && it->srcPort == srcPort && it->destAddr == destAddr && it->destPort == destPort) {
            return i;
        }
    }
    return -1;
}

void genPseudoHeader(unsigned char* ptr, uint32_t srcAddr, uint32_t destAddr, uint16_t len){
    memset(ptr, htonl(srcAddr), sizeof(srcAddr));
    memset(ptr+32, htonl(destAddr), sizeof(destAddr));
    memset(ptr+72, 0x6, sizeof(char));
    memset(ptr+80, htons(len), sizeof(len));
}

// checksum in n-order
// checksum starts at 224 byte
uint16_t getChecksumNet(uint16_t* temp, int n_trunks, int checksum_idx=14){
    uint32_t checksum = 0;
    for(int i = 0; i < n_trunks; i++){
        if(i == checksum_idx) continue;
        checksum += temp[i];
        checksum = (checksum >> 16) + (checksum & 0xffff);
    }

    return htons((uint16_t)checksum);
}

int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr){
    TCPHeaderInfo info = TCPHeaderInfo(pBuffer);
    printf("[INPUT] ");
    info.print();


}

void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr){

    bool is_syn = false;
    bool is_ack = false;
    bool is_fin = false;
    if(flag == PACKET_TYPE_SYN){ is_syn = true; }
    else if (flag == PACKET_TYPE_SYN_ACK) { is_syn = true; is_ack = true; }
    else if (flag == PACKET_TYPE_ACK) { is_ack = true; }
    else if (flag == PACKET_TYPE_FIN) { is_fin = true; }
    else if (flag == PACKET_TYPE_FIN_ACK) { is_fin = true;  is_ack = true;}

    uint32_t nextSeqNo = 0;
    uint32_t nextAckNo = 0;
    uint16_t nextWindow = 0;

    // make a packet

    int n_trunks = ((len+15) / 16 + 10);  // tcp header + pseudo header
    unsigned char* temp = new unsigned char[n_trunks * 16];
    memset(temp, 0, n_trunks * 16);
    memcpy(temp, pData, len);

    genPseudoHeader(temp, srcAddr, dstAddr, 64 + len);  // tcp header + tcp data

    // make head
    struct tcpHead head;

    head.srcPort = htons(srcPort);
    head.destPort = htons(dstPort);
    head.seqNo = htons(nextSeqNo);
    head.ackNo = htons(nextAckNo);
    head.windowsize = htons(nextWindow);

    head.headLen = 5 << 4;  // min=5

    head.flag = 0;
    if(is_ack) head.flag &= (0x1 << 4);
    if(is_syn) head.flag &= (0x1 << 1);
    if(is_fin) head.flag &= (0x1);

    memcpy(temp + 96, &head, 64);

    // compute checksum
    uint16_t checksumNet = getChecksumNet((uint16_t*)temp, n_trunks);
    memset(temp, checksumNet, sizeof(checksumNet));

    // send packet
    tcp_sendIpPkt(temp+96, len+64, srcAddr, dstAddr, 64);
}

int stud_tcp_socket(int domain, int type, int protocol){
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen){
}

int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags){

}

int stud_tcp_recv(int sockfd, unsigned char *pData, unsigned short datalen, int flags){
}

int stud_tcp_close(int sockfd){

}