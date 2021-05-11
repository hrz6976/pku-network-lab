// Simplified TCP Transmission (Client)
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

extern int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr);
extern void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr);

#define MAX_OPEN_FD 100
#define PORT_OFFSET 1024
#define DEFAULT_ACK 1
#define DEFAULT_SEQ 1

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
    UNUSED, SYN_SENT, ESTABLISHED, FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSED
};

struct TCBEntry {
    uint32_t srcAddr, destAddr;
    uint16_t srcPort, destPort;
    uint32_t window, recvSeq, sendSeq;  // for next send packet or recv packet
    uint16_t status = UNUSED;

    void print(){
        printf("srcPort = %d destPort = %d ", srcPort, destPort);
        printf("sendSeq = %d, recvSeq = %d ", sendSeq, recvSeq);
        printf("windowSize = %d, status = %d ", window, status);
        printf("\n");
    }
};

TCBEntry TCBTable[MAX_OPEN_FD];

// return index of tcb (addr)
int getTcbByIp(uint32_t srcAddr, uint16_t srcPort, uint32_t destAddr, uint32_t destPort) {
    for (int i = 0; i < MAX_OPEN_FD; i++) {
        TCBEntry *it = &TCBTable[ i ];
        if (it->srcAddr == srcAddr && it->srcPort == srcPort && it->destAddr == destAddr && it->destPort == destPort) {
            return i;
        }
    }
    return -1;
}

// return index of empty tcp
int getTcbEmpty(){
    for(int i = 0; i < MAX_OPEN_FD; i++){
        TCBEntry* it = &TCBTable[i];
        if(it->status == UNUSED){
            return i;
        }
    }
    return -1;
}

void genPseudoHeader(unsigned char* ptr, uint32_t srcAddr, uint32_t destAddr, uint16_t len){
    memset(ptr, htonl(srcAddr), sizeof(srcAddr));
    memset(ptr+4, htonl(destAddr), sizeof(destAddr));
    memset(ptr+9, 0x6, sizeof(char));
    memset(ptr+10, htons(len), sizeof(len));
}

// checksum in n-order
// checksum starts at 224 byte
uint16_t getChecksumNet(uint16_t* temp, int n_trunks, int checksum_idx=14){
    uint32_t checksum = 0;
    for(int i = 0; i < n_trunks; i++){
        if(i == checksum_idx) continue;
        checksum += ntohs(temp[i]);
        checksum = (checksum >> 16) + (checksum & 0xffff);
    }

    return htons((uint16_t)checksum);
}

int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr){
    TCPHeaderInfo info = TCPHeaderInfo(pBuffer);
    printf("[INPUT] ");
    info.print();

    int n_trunks = (len+1) / 2 + 10;  // tcp header + pseudo header
    unsigned char* temp = new unsigned char[n_trunks * 2];  // 1 chunk = 2 bytes, 16 bits
    memset(temp, 0, n_trunks * 2);
    memcpy(temp + 12, pBuffer, len);  // tcp header starts at 96

    genPseudoHeader(temp, srcAddr, dstAddr, 8 + len);  // tcp header + tcp data
    uint16_t checksumNet = getChecksumNet((uint16_t*)temp, n_trunks);
    printf("[INPUT] expect checksum %x, got checksum=%x\n", info.checksumNet, checksumNet);
    if(checksumNet != info.checksumNet){  // mismatch
        tcp_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return 1;
    }

    // lookup connection in table
    int connIdx = getTcbByIp(srcAddr, info.srcPort, dstAddr, info.destPort);
    assert(connIdx != -1);
    if(TCBTable[connIdx].status == SYN_SENT){
        // expect Syn Ack
        if(!(info.is_syn && info.is_ack)) return 1;
        if(info.ackNo != TCBTable[connIdx].sendSeq + 1){
            tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
            return 1;
        }
        // valid Syn Ack
        TCBTable[connIdx].sendSeq += 1;
        TCBTable[connIdx].recvSeq = info.seqNo + 1;
        TCBTable[connIdx].status = ESTABLISHED;

        // send Ack
        stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
                        TCBTable[connIdx].srcPort, TCBTable[connIdx].destPort,
                        srcAddr, dstAddr);

    }else if(TCBTable[connIdx].status == ESTABLISHED){  // expect valid transmission


    }else if(TCBTable[connIdx].status == FIN_WAIT1){
        // expect Ack
        if(!info.is_ack) return 1;
        if(info.ackNo != TCBTable[connIdx].sendSeq + 1){
            tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
            return 1;
        }
        // valid Ack
        TCBTable[connIdx].status = FIN_WAIT2;

    }else if(TCBTable[connIdx].status == FIN_WAIT2){ // expect fin ack
        // expect Fin Ack
        if(!info.is_ack || !info.is_fin) return 1;
        if(info.ackNo != TCBTable[connIdx].sendSeq + 1){
            tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
            return 1;
        }
        // valid Fin Ack
        TCBTable[connIdx].status = CLOSED;
        // send Fin Ack
        stud_tcp_output(NULL, 0, PACKET_TYPE_FIN_ACK,
                        TCBTable[connIdx].srcPort, TCBTable[connIdx].destPort,
                        srcAddr, dstAddr);
    }
    return 0;
}

void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr){
    // [0-95] pseudo header  [96-159] tcp header [160-N] payload
    bool is_syn = false;
    bool is_ack = false;
    bool is_fin = false;
    if(flag == PACKET_TYPE_SYN){ is_syn = true; }
    else if (flag == PACKET_TYPE_SYN_ACK) { is_syn = true; is_ack = true; }
    else if (flag == PACKET_TYPE_ACK) { is_ack = true; }
    else if (flag == PACKET_TYPE_FIN) { is_fin = true; }
    else if (flag == PACKET_TYPE_FIN_ACK) { is_fin = true;  is_ack = true;}

    int connIdx = getTcbByIp(srcAddr, info.srcPort, dstAddr, info.destPort);
    assert(connIdx != -1);

    uint32_t nextSeqNo = TCBTable[connIdx].sendSeq;
    uint32_t nextAckNo = TCBTable[connIdx].recvSeq;
    uint16_t nextWindow = 0;

    // make a packet

    int n_trunks = (len+1) / 2 + 10;  // tcp header + pseudo header
    unsigned char* temp = new unsigned char[n_trunks * 2];  // 1 chunk = 2 bytes, 16 bits
    memset(temp, 0, n_trunks * 2);
    memcpy(temp + 20, pData, len);  // data starts at 160

    genPseudoHeader(temp, srcAddr, dstAddr, 8 + len);  // tcp header + tcp data

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

    memcpy(temp + 12, &head, sizeof(head));

    // compute checksum
    uint16_t checksumNet = getChecksumNet((uint16_t*)temp, n_trunks);
    memset(temp, checksumNet, sizeof(checksumNet));

    TCPHeaderInfo info = TCPHeaderInfo((char*)temp + 12);
    printf("[INPUT] ");
    info.print();

    // send packet without pseudo header?
    tcp_sendIpPkt(temp, len + 20, srcAddr, dstAddr, 64);
}

int stud_tcp_socket(int domain, int type, int protocol){  // allocate a new socket
    int emptyIdx = getTcbEmpty();
    assert(emptyIdx != -1);

    TCBTable[emptyIdx].status = CLOSED;
    TCBTable[emptyIdx].srcAddr = getIpv4Address();
    TCBTable[emptyIdx].srcPort = PORT_OFFSET + emptyIdx;
    TCBTable[emptyIdx].sendSeq = DEFAULT_ACK;
    TCBTable[emptyIdx].recvSeq = DEFAULT_SEQ;

    return emptyIdx;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen){
    TCBEntry* it = &TCBTable[sockfd];
    it->destAddr = ntohl(addr->sin_addr.s_addr);  // uint32
    it->destPort = ntohs(addr->sin_port); // uint16

    char* buffer[1024];

    // send syn
    stud_tcp_output(NULL, 0, PACKET_TYPE_SYN, it->srcPort, it->destPort, it->srcAddr, it->destAddr);
    it->status = SYN_SENT;

    // wait for syn ack
    waitIpPacket((char*)buffer,6);
    TCPHeaderInfo info = TCPHeaderInfo((char*)buffer);
    if(info.is_ack && info.is_syn){
        it->recvSeq = info.seqNo + 1;
        it->sendSeq = info.seqNo + 1;
        it->status = ESTABLISHED;
    } else {
        return 1;  // failed
    }
    // send ack
    stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, it->srcPort, it->destPort, it->srcAddr, it->destAddr);
    return 0;
}

int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags){

}

int stud_tcp_recv(int sockfd, unsigned char *pData, unsigned short datalen, int flags){
}

int stud_tcp_close(int sockfd){
    // send fin
    // wait for fin ack
    // wait for fin
    // send fin ack

}