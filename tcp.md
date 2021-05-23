#### 0. 数据结构及工具函数

##### 0.1 TCPHeaderInfo

TCPHeaderInfo类的构造函数从TCP头中读出我们需要的信息。将这个操作提取出来可以尽可能实现代码复用。


```cpp
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
```

##### 0.1 TCP状态

在Netriver的简化TCP中，只有`SYN_SENT, ESTABLISHED, FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSED`这几个状态。在这里我们为了简化查找空TCB的过程，将状态0定义为UNUSED。


```cpp
enum TCPStatus {
    UNUSED, SYN_SENT, ESTABLISHED, FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSED
};
```

<img src="C:\Users\hrz\AppData\Roaming\Typora\typora-user-images\image-20210523221630849.png" alt="image-20210523221630849" style="zoom:50%;" />

<center>Netriver简化的TCP状态机</center>

##### 0.2 TCB

在TCB中，我们保存源和目标的地址与端口（注意这里都是主机序）。`nextAck`与`nextSeq`保存下一个即将发送的包的ACK和SEQ值。由于简化TCP是停等协议，因此这里WindowSize定义为1，初始状态为UNUSED。


```cpp
// When sending new packet:
// seq = nextSeq, ack = nextAck
struct TCBEntry {
    uint32_t srcAddr, destAddr;
    uint16_t srcPort, destPort;
    uint32_t window, nextAck, nextSeq;
    uint16_t status = UNUSED;

    void print(){
        printf("srcPort = %d destPort = %d ", srcPort, destPort);
        printf("nextSeq = %d, nextAck = %d ", nextSeq, nextAck);
        printf("windowSize = %d, status = %d ", window, status);
        printf("\n");
    }
};

TCBEntry TCBTable[MAX_OPEN_FD];
```

我们将TCB表以数组的形式保存。

`getTcbByIp`函数根据源和目标的地址及端口在TCB表中查找项，若查找成功返回索引值，若查找失败返回-1。

`getTcbEmpty`函数返回第一个状态为UNUSED的TCB的索引。

```cpp
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
```

##### 0.3 TCP伪头部生成

为了计算TCP包的校验值，我们需要根据源和目标的地址、协议、数据报长度生成一个伪头部。TCP伪头部定义如以下：

![image-20210523222415247](C:\Users\hrz\AppData\Roaming\Typora\typora-user-images\image-20210523222415247.png)

`genPseudoHeader`函数将在从ptr开始的12Byte中生成一个伪头部：（参数均为主机序）

```cpp
void genPseudoHeader(unsigned char* ptr, uint32_t srcAddr, uint32_t destAddr, uint16_t len){
    memset(ptr, htonl(srcAddr), sizeof(srcAddr));
    memset(ptr+4, htonl(destAddr), sizeof(destAddr));
    memset(ptr+9, 0x6, sizeof(char));
    memset(ptr+10, htons(len), sizeof(len));
}
```

##### 0.4 计算校验和

`getCheckSumNet`函数按照我们熟悉的carry-add算法生成TCP校验和。注意这里忽略了校验和所在的字段，因此判断数据包校验和是否正确时采用`curr_checksum==checksum`。

```cpp
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
```



#### 1. TCP分组接收和发送

##### 1.1 stud_tcp_output

```cpp
void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr){
    printf("[OUT] len=%d flag=%d srcPort=%d dstPort=%d srcAddr=%x dstAddr=%x\n", len, flag, srcPort, dstPort, srcAddr, dstAddr);
    printf("[OUT] data=");
    for(int i = 0; i < len; i++) printf("%x ", pData[i]);

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
    }else if(TCBTable[connIdx].status == ESTABLISHED && (flag == PACKET_TYPE_FIN_ACK || flag == PACKET_TYPE_FIN)){  // closing connection    // Why FIN ACK?
        printf("[OUT] (%d) Entering FIN_WAIT1\n", connIdx);
        TCBTable[connIdx].status = FIN_WAIT1;
    }

    // send packet with pseudo header?
    tcp_sendIpPkt(temp + 12, len + 20, srcAddr, dstAddr, 60);
}
```

当我们发送一个TCP数据包时：

1. 获取TCB（此时连接连接若没有建立，则新创建一个TCB）
2. 根据TCB和参数生成TCP头（注意头文件中tcphead的大小不是20，而是24）
3. 发送包
4. 状态变化：
   1. flag是SYN，说明正在建立新连接，连接的状态变化为SYN_SENT
   2. flag是FIN_ACK（注意这里的实现与正常TCP不同）时，说明正在关闭连接，状态变化为FIN_WAIT1

![image-20210523223056363](C:\Users\hrz\AppData\Roaming\Typora\typora-user-images\image-20210523223056363.png)

<center>TCP头数据结构</center>

|size |pseudo header | tcp header | payload |
|----|----|----|----|
| Bits| [0-95] |[96-159]  |[160-N]|
| Bytes| [0-11] |[12-19]   |[20-N]|
| Ints| [0-5] |[6-9]    |[10-N]|
| Words| [0-2] |[3-4]    |[5-N]|

这里为了实现简便，我们规定TCP头长度为160bit（5 words），这也是TCP协议允许的最小头部大小。



##### 1.2 stud_tcp_input

```cpp
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

    // what the f*ck, Why addr in n-order
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
```

当我们接受一个TCP数据包时，需要：

1. 读出TCP头中的信息，生成伪头部并计算校验和（注意这里参数srcAddr, dstAddr与发送函数不同，以网络序给出）
2. 查找TCB（这时连接肯定已经建立）
3. 状态变化：
   1. 状态为SYN_SENT且返回SYN_ACK，连接建立，状态转为ESTABLISHED，发送ACK；
   2. 状态为ESTABLISHED且返回ACK，根据ACK数据包的SEQ和ACK值更新nextSeq与nextAck（这里的实现与正常TCP相同，若没有payload seq+=1，若有payload，seq+=len(payload)；
   3. 状态为FIN_WAIT1且返回ACK，状态进入FIN_WAIT2，等待下一个数据包；
   4. 状态为FIN_WAIT2且返回FIN_ACK，结束连接，状态转为CLOSED，并发送ACK数据包。



#### 2. TCP Socket 实现

##### 2.1 stud_tcp_socket

`stud_tcp_socket`函数查找第一个状态为UNUSED的TCB，将其初始化并返回一个sockfd。（注意sockfd作为file descriptor，其值一定大于0。这里将其加上一个offest 114）

```cpp
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
```

##### 2.2 stud_tcp_connect

注意这里请求数据包经常失败（可能是netriver返回数据包的时间间隔太长）。为了尽可能复用代码，我们设计了包装函数`waitIpPacketWrapper`：

```cpp
int waitIpPacketWrapper(char* buffer){
    int res = -1;
    int tries = 0;
    while((res = waitIpPacket((char*)buffer,6000)) == -1){
        if(tries++ == 10) break;
    }
    return res;
}
```

```cpp
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
    if(waitIpPacketWrapper((char*)buffer) == -1) return -1;
    stud_tcp_input(buffer, 20, htonl(it->destAddr), htonl(it->srcAddr));

    return 0;
}
```

当Client与Server建立TCP连接时，需要：

1. 根据sockfd获取TCB
2. 发送SYN数据包
3. 等待Server返回SYN_ACK

##### 2.3 stud_tcp_send

```cpp
int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags){
    sockfd -= SOCK_OFFSET; // OFFSET
    if (sockfd < 0 || sockfd >= MAX_OPEN_FD || TCBTable[sockfd].status != ESTABLISHED) return -1;
    TCBEntry* it = &TCBTable[sockfd];
    printf("[SEND] (%d) len=%d flags=%x data=", datalen, flags);
    for(int i = 0; i < datalen; i++) printf("%x ", pData[i]);
    it->print();

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
```

当Client向Server发送数据包时，需要：

1. 根据sockfd获取TCB
2. 发送SYN数据包
3. 等待Server返回ACK
4. 根据返回的数据包进行状态转移（由于过于复杂，这里直接调用`stud_tcp_input`函数）

##### 2.4 stud_tcp_recv

```cpp
int stud_tcp_recv(int sockfd, unsigned char *pData, unsigned short datalen, int flags){
    sockfd -= SOCK_OFFSET; // OFFSET
    printf("[RECV] (%d) len=%d flags=%x \n", sockfd, datalen, flags);
    if( sockfd < 0 || sockfd >= MAX_OPEN_FD || TCBTable[sockfd].status != ESTABLISHED) return -1;
    TCBEntry* it = &TCBTable[sockfd];
    printf("[RECV] ");
    it->print();

    // expect Data
    memset(buffer, 0, sizeof(buffer));
    int tcp_len = 20;
    if((tcp_len = waitIpPacketWrapper((char*)buffer)) == -1) return -1;

    TCPHeaderInfo info = TCPHeaderInfo(buffer);
    int headerLength = info.headLen << 2;

    printf("[RECV] ipv4 payload length = %d, data length = %d\n", tcp_len, tcp_len - headerLength);

    
    memcpy(pData, buffer + headerLength, tcp_len - headerLength);
    
    // manually handle mutation here
    it->nextSeq = info.ackNo;
    it->nextAck = info.seqNo + (tcp_len>20 ? tcp_len-20: 1);

    // send Ack
    stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, it->srcPort, it->destPort, it->srcAddr, it->destAddr);

    return 0;
}
```

注意这个接口仅仅负责数据的接收，并不处理状态转移。

`stud_tcp_recv`函数接收一个TCP数据包，并将TCP Payload放入pData：

1. 接收一个数据包
2. 根据sockfd得到TCB，并计算Seq和Ack值
3. 将payload复制到pData
4. 发送ACK数据包

##### 2.5 stud_tcp_close

```cpp
int stud_tcp_close(int sockfd){
    sockfd -= SOCK_OFFSET; // OFFSET
    printf("[CLOSE] (%d)", sockfd);
    if( sockfd < 0 || sockfd >= MAX_OPEN_FD || TCBTable[sockfd].status != ESTABLISHED) return -1;
    TCBEntry* it = &TCBTable[sockfd];
    it->print();

    // send fin
    // Why FIN ACK?
    stud_tcp_output(NULL, 0, PACKET_TYPE_FIN_ACK, it->srcPort, it->destPort, it->srcAddr, it->destAddr);
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
```

当关闭一个TCP连接时，需要完成四次挥手：

1.  发送一个FIN_ACK
2. 等待ACK
3. 等待FIN_ACK
4. 发送ACK

#### 3. 吐槽

1. 实验指导书有些地方没有说清楚细节，尤其是TCP实验（例如状态转换时的数据包flag，和参数的字节序）
2. 编译器版本过于古老，无法使用较新的c++特性
3. Netriver的调试器聊胜于无，并且错误输出让人类难以理解，debug十分痛苦
4. Netriver有时自己会崩溃，并产生一些玄学错误（这可能是历史原因？）
5. 建议课堂讲授内容中包括一些实习（指Wireshark作业和Netriver)