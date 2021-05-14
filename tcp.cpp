// Simplified TCP Transmission (Client)
// 12f23eddde <rzhe@pku.edu.cn> - May 10 2021
#include "sysInclude.h"

#include <cstdlib>
#include <cstring>
#include <vector>
#include <iostream>

// make idea happy
//#include <netinet/in.h>

using namespace std;

extern void tcp_DiscardPkt(char * pBuffer, int type);
extern void tcp_sendIpPkt(unsigned char* pData, uint16 len, unsigned int srcAddr, unsigned int dstAddr, uint8 ttl);
extern int waitIpPacket(char *pBuffer, int timeout);
extern void tcp_sendReport(int type);
extern UINT32 getIpv4Address( );
extern UINT32 getServerIpv4Address( );

#define MAX_OPEN_FD 100
#define PORT_OFFSET 2005
#define SOCK_OFFSET 114
#define DEFAULT_ACK 0
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
        memcpy(&head, pBuffer, sizeof(head)); // copy from Buffer
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
    }

    void print() {
        printf("src=%d dest=%d seq=%d ack=%d len=%d ws=%d |", srcPort, destPort, seqNo, ackNo, headLen, windowsize);
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

// When sending new packet:
// seq = nextSeq, ack = nextAck
struct TCBEntry {
    uint32_t srcAddr, destAddr;
    uint16_t srcPort, destPort;
    uint32_t window, nextAck, nextSeq;
    uint16_t status;

    void print(){
        printf("srcAddr = %8x destPort = %8x ", srcAddr, destAddr);
        printf("srcPort = %d destPort = %d ", srcPort, destPort);
        printf("nextSeq = %d, nextAck = %d ", nextSeq, nextAck);
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

// return index of empty tcb
int getTcbEmpty(){
    for(int i = 0; i < MAX_OPEN_FD; i++){
        TCBEntry* it = &TCBTable[i];
        if(it->status == UNUSED){
            return i;
        }
    }
    return -1;
}

// expect all arguments in h-order
void genPseudoHeader(unsigned char* ptr, uint32_t srcAddr, uint32_t destAddr, uint16_t len, bool from_local=true){
    // pseudo header must in n-order
    if(from_local){
        srcAddr = htonl(srcAddr);
        destAddr = htonl(destAddr);
        len = htons(len);
    }
    int TCP = 0x6;
    memcpy(ptr, &srcAddr, sizeof(srcAddr));
    memcpy(ptr+4, &destAddr, sizeof(destAddr));
    memcpy(ptr+9, &TCP, sizeof(char));
    memcpy(ptr+10, &len, sizeof(len));
}

// checksum in n-order
// checksum starts at 224 byte
uint16_t getChecksumNet(uint16_t* temp, int n_trunks, int checksum_idx=14){
    uint32_t checksum = 0;
    for(int i = 0; i < n_trunks; i++){
        printf("%4x ", ntohs(temp[i]));  // print in n-order
        if(i == checksum_idx) continue;
        checksum += ntohs(temp[i]);
        // checksum = (checksum >> 16) + (checksum & 0xffff);
    }

    while(checksum > 0xffff) checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = (~checksum) & 0xffff;
    printf("checksum=%x\n", checksum);

    return htons((uint16_t)checksum);
}

char buffer[1024];  // global buffer

// pseudo header | tcp header | payload
// Bits:  [0-95] |[96-255]    |[256-N]
// Bytes: [0-11] |[12-31]     |[32-N]
// Ints:  [0-5]  |[6-15]      |[16-N]
// Words: [0-2]  |[3-7]       |[8-N]
void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr){
    printf("[OUT] len=%d flag=%d srcPort=%d dstPort=%d srcAddr=%x dstAddr=%x\n", len, flag, srcPort, dstPort, srcAddr, dstAddr);
    printf("[OUT] data=");
    for(int i = 0; i < len; i++) printf("%x ", pData[i]);

    // bool is_syn = false;
    // bool is_ack = false;
    // bool is_fin = false;

    int connIdx = getTcbByIp(srcAddr, srcPort, dstAddr, dstPort);
    if(connIdx == -1){  // new connection
        int emptyIdx = getTcbEmpty();
        assert(emptyIdx != -1);

        TCBEntry *it = &TCBTable[emptyIdx];  // uninited
        memset(it, 0, sizeof(TCBEntry));
        it->status = CLOSED;
        it->srcAddr = srcAddr;
        it->destAddr = dstAddr;
        it->srcPort = srcPort;
        it->destPort = dstPort;
        it->nextSeq = DEFAULT_SEQ + emptyIdx;
        it->nextAck = DEFAULT_ACK;
        it->window = 1;  // stop n wait
        it->print();
        connIdx=emptyIdx;
    }
    printf("[OUT] (%d) ",connIdx);
    TCBTable[connIdx].print();

    uint32_t nextSeqNo = TCBTable[connIdx].nextSeq;
    uint32_t nextAckNo = TCBTable[connIdx].nextAck;
    uint16_t nextWindow = TCBTable[connIdx].window;

    // make a packet
    int n_trunks = (len+1) / 2 + 16;  // tcp header + pseudo header
    unsigned char* temp = new unsigned char[n_trunks * 2];  // 1 chunk = 2 bytes, 16 bits
    memset(temp, 0, n_trunks * 2);
    memcpy(temp + 32, pData, len);  // data starts at 256

    genPseudoHeader(temp, srcAddr, dstAddr, 20 + len);  // tcp header + tcp data

    // make head
    struct tcpHead head;

    memset(&head, 0, sizeof(head));

    head.srcPort = htons(srcPort);
    head.destPort = htons(dstPort);
    head.seqNo = htonl(nextSeqNo);
    head.ackNo = htonl(nextAckNo);
    head.windowsize = htons(nextWindow);
    head.headLen = 5 << 4;  // min=5
    head.flag = flag;

    memcpy(temp + 12, &head, 20);  // why sizeof(head)=24

    // compute checksum
    uint16_t checksumNet = getChecksumNet((uint16_t*)temp, n_trunks);
    memcpy(temp + 28, &checksumNet, sizeof(checksumNet));

    TCPHeaderInfo info = TCPHeaderInfo((char*)temp + 12);
    printf("[OUT] ");
    info.print();

    // state mutation
    if(TCBTable[connIdx].status == CLOSED && flag == PACKET_TYPE_SYN){  // new connection
        printf("[OUT] (%d) Entering SYN_SENT\n", connIdx);
        TCBTable[connIdx].status = SYN_SENT;
    }else if(TCBTable[connIdx].status == ESTABLISHED && (flag == PACKET_TYPE_FIN_ACK || flag == PACKET_TYPE_FIN)){  // closing connection    // Why FIN+ACK?
        printf("[OUT] (%d) Entering FIN_WAIT1\n", connIdx);
        TCBTable[connIdx].status = FIN_WAIT1;
    }

    // send packet with pseudo header?
    tcp_sendIpPkt(temp + 12, len + 20, srcAddr, dstAddr, 60);  // Why 60?
}

int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr){  // expect all arg in h-order
    printf("[IN] len=%d srcAddr=%x dstAddr=%x\n", len, srcAddr, dstAddr);  // len: tcp header + tcp data
    printf("[IN] data=");
    for(int i = 0; i < len; i++) printf("%x ", pBuffer[i]);
    TCPHeaderInfo info = TCPHeaderInfo(pBuffer);
    printf("[INPUT] ");
    info.print();

    int n_trunks = (len+1) / 2 + 6;  // tcp header + pseudo header
    unsigned char* temp = new unsigned char[n_trunks * 2];  // 1 chunk = 2 bytes, 16 bits
    memset(temp, 0, n_trunks * 2);

    // what the f*ck, why addr in n-order
    srcAddr = ntohl(srcAddr);
    dstAddr = ntohl(dstAddr);

    genPseudoHeader(temp, srcAddr, dstAddr, len);  // tcp header + tcp data
    memcpy(temp + 12, pBuffer, len);  // header starts at 96
    uint16_t checksumNet = getChecksumNet((uint16_t*)temp, n_trunks);
    printf("[INPUT] expect checksum %x, got checksum=%x\n", info.checksumNet, checksumNet);
    if(checksumNet != info.checksumNet){  // mismatch
        tcp_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return 1;
    }

    // lookup connection in table
    int connIdx = getTcbByIp(dstAddr, info.destPort, srcAddr, info.srcPort);
    if(connIdx == -1) printf("[INPUT] connection not found\n");
    assert(connIdx != -1);
    printf("[IN] (%d) ",connIdx);
    TCBTable[connIdx].print();

    if(TCBTable[connIdx].status == SYN_SENT){
        // expect Syn Ack
        if(!(info.is_syn && info.is_ack)) return 1;
        if(info.ackNo != TCBTable[connIdx].nextSeq + 1){  // seq of packet sent
            tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
            return 1;
        }
        // valid Syn Ack
        TCBTable[connIdx].nextSeq = info.ackNo;
        TCBTable[connIdx].nextAck = info.seqNo + 1;
        TCBTable[connIdx].status = ESTABLISHED;
        printf("[IN] (%d) Entering ESTABLISHED\n", connIdx);

        // send Ack
        stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
                        TCBTable[connIdx].srcPort, TCBTable[connIdx].destPort,
                        TCBTable[connIdx].srcAddr, TCBTable[connIdx].destAddr);

    }else if(TCBTable[connIdx].status == ESTABLISHED){  // expect valid transmission
        if(!info.is_ack){  // data
            return 0;
        } else if (!info.is_syn){  // ack
            TCBTable[connIdx].nextSeq = info.ackNo;
            TCBTable[connIdx].nextAck = info.seqNo + (len>20 ? len-20: 1);
        } else return 1;
    }else if(TCBTable[connIdx].status == FIN_WAIT1){
        // expect Ack
        if(!info.is_ack || info.is_fin) return 1;
        if(info.ackNo != TCBTable[connIdx].nextSeq + 1){
            tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
            return 1;
        }
        // valid Ack
        TCBTable[connIdx].status = FIN_WAIT2;
        printf("[IN] (%d) Entering FIN_WAIT2\n", connIdx);

    }else if(TCBTable[connIdx].status == FIN_WAIT2){ // expect fin ack
        // expect Fin Ack
        if(!info.is_ack || !info.is_fin) return 1;
        if(info.ackNo != TCBTable[connIdx].nextSeq + 1){
            tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
            return 1;
        }
        TCBTable[connIdx].nextSeq = info.ackNo;
        TCBTable[connIdx].nextAck = info.seqNo + 1;
        // valid Fin Ack
        TCBTable[connIdx].status = CLOSED;
        printf("[IN] (%d) Entering CLOSED\n", connIdx);
        // send Ack
        stud_tcp_output(NULL, 0, PACKET_TYPE_ACK,
                        TCBTable[connIdx].srcPort, TCBTable[connIdx].destPort,
                        TCBTable[connIdx].srcAddr, TCBTable[connIdx].destAddr);
    }
    return 0;
}

int stud_tcp_socket(int domain, int type, int protocol){  // allocate a new socket  // Why Sockfd > 0?
    int emptyIdx = getTcbEmpty();
    assert(emptyIdx != -1);

    TCBEntry *it = &TCBTable[emptyIdx];  // uninited
    memset(it, 0, sizeof(TCBEntry));
    it->status = CLOSED;
    it->srcAddr = getIpv4Address();
    it->srcPort = emptyIdx + PORT_OFFSET;
    it->nextSeq = DEFAULT_SEQ + emptyIdx;
    it->nextAck = DEFAULT_ACK;
    it->window = 1;  // stop n wait

    printf("[SOCKET] ");
    it->print();

    return emptyIdx + SOCK_OFFSET;
}

int waitIpPacketWrapper(char* buffer){
    int res = -1;
    int tries = 0;
    while((res = waitIpPacket((char*)buffer,6000)) == -1){
        if(tries++ == 10) break;
    }
    return res;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen){
    printf("[CONN] sockfd=%d, addr=%x\n", sockfd, ntohl(addr->sin_addr.s_addr));
    sockfd -= SOCK_OFFSET; // OFFSET
    if(sockfd < 0 || sockfd >= MAX_OPEN_FD || TCBTable[sockfd].status == UNUSED){
        return -1;
    }
    TCBEntry* it = &TCBTable[sockfd];
    it->destAddr = ntohl(addr->sin_addr.s_addr);  // uint32
    it->destPort = ntohs(addr->sin_port); // uint16

    // send syn
    stud_tcp_output(NULL, 0, PACKET_TYPE_SYN, it->srcPort, it->destPort, it->srcAddr, it->destAddr);
    it->status = SYN_SENT;

    // wait for syn ack
//    char buffer[128];
    if(waitIpPacketWrapper((char*)buffer) == -1) return -1;
    stud_tcp_input(buffer, 20, htonl(it->destAddr), htonl(it->srcAddr));

    return 0;
}

int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags){
    sockfd -= SOCK_OFFSET; // OFFSET
    TCBEntry* it = &TCBTable[sockfd];
    printf("[SEND] (%d) len=%d flags=%x data=", datalen, flags);
    for(int i = 0; i < datalen; i++) printf("%x ", pData[i]);
    it->print();

//    char buffer[1024];
    strcpy(buffer, (char*)pData);
    
    if(it->status != ESTABLISHED){
        return -1;
    }
    stud_tcp_output((char*)pData, datalen, PACKET_TYPE_DATA, it->srcPort, it->destPort, it->srcAddr, it->destAddr);

    // expect Ack
    memset(buffer, 0, sizeof(buffer));
    int tcp_len = 20;
    if((tcp_len = waitIpPacketWrapper((char*)buffer)) == -1) return -1;

    printf("[SEND] ipv4 payload length = %d\n", tcp_len);
    stud_tcp_input(buffer, tcp_len, htonl(it->destAddr), htonl(it->srcAddr));
    return 0;
}

int stud_tcp_recv(int sockfd, unsigned char *pData, unsigned short datalen, int flags){
    sockfd -= SOCK_OFFSET; // OFFSET
    printf("[RECV] (%d) len=%d flags=%x \n", sockfd, datalen, flags);
    TCBEntry* it = &TCBTable[sockfd];
    printf("[RECV] ");
    it->print();

    if(it->status != ESTABLISHED){
        return -1;
    }

    // expect Data
//    char buffer[128];
    memset(buffer, 0, sizeof(buffer));
    int tcp_len = 20;
    if((tcp_len = waitIpPacketWrapper((char*)buffer)) == -1) return -1;
    
    printf("[RECV] ipv4 payload length = %d\n", tcp_len);

    // stud_tcp_input(buffer, tcp_len, htonl(it->destAddr), htonl(it->srcAddr));
    memcpy(pData, buffer, tcp_len);

    // send Ack
    stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, it->srcPort, it->destPort, it->srcAddr, it->destAddr);

    return 0;
}

int stud_tcp_close(int sockfd){
    sockfd -= SOCK_OFFSET; // OFFSET
    TCBEntry* it = &TCBTable[sockfd];
    printf("[CLOSE] ");
    it->print();

    // send fin
    stud_tcp_output(NULL, 0, PACKET_TYPE_FIN, it->srcPort, it->destPort, it->srcAddr, it->destAddr);
    // wait for ack

    memset(buffer, 0, sizeof(buffer));
    if(waitIpPacketWrapper((char*)buffer) == -1) return -1;
    stud_tcp_input(buffer, 20, htonl(it->destAddr), htonl(it->srcAddr));
    // wait for fin ack
    if(waitIpPacketWrapper((char*)buffer) == -1) return -1;
    stud_tcp_input(buffer, 20, htonl(it->destAddr), htonl(it->srcAddr));
    // send ack
    return 0;
}