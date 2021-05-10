#### 1. 接收接口

由于发送接口的实现可以看做接收接口的逆向，因此我们着重介绍接收接口的实现。

##### 1.1 IPv4 header的数据结构


```cpp
int stud_ip_recv(char *pBuffer,unsigned short length){
	struct IPHead ipv4Header;
	memcpy(&ipv4Header, pBuffer, sizeof(struct IPHead));
```

<img src="/Users/Apple/Library/Application Support/typora-user-images/image-20210426212604101.png" alt="image-20210426212604101" style="zoom:50%;" />

<center>IPv4 Header数据结构</center>

参照上图，IPv4 header的长度一般为20字节；而后的数据位在这个实验中我们并不关心。

##### 1.1 版本

```cpp
	uint8_t version = ipv4Header.ver >> 4;
	// version error
	if(version != 4){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
		printf("[RECV] ver!=4\n");
		return STUD_IP_TEST_VERSION_ERROR;
	}
```

版本占4bit，是IPHead.ver的高4位。IPv4的版本为4。若version不是4，则调用ip_DiscardPkt函数，丢弃包。

##### 1.2 首部长度

```cpp
	// header length error
	// 4 bit version & headerLength (x4->bytes)
	uint8_t headerLength = ipv4Header.ver & 0xf;
	if(headerLength <= 4){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
		printf("[RECV] len<=4\n");
		return STUD_IP_TEST_HEADLEN_ERROR;
	}
```

首部长度占4bit，是IPHead.ver的低4位。需要注意的是，长度以4bytes为单位；20bytes对应的值是5。事实上，合法IPv4 Header的最小长度就是20bytes，因此首部长度<=4时我们需要丢弃包。

##### 1.3 TTL

```cpp
	uint8_t ttl = ipv4Header.ttl;
	// ttl error
	if (ttl <= 0){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
		printf("[RECV] ttl<=0\n");
		return STUD_IP_TEST_TTL_ERROR;
	}
```

在IP协议中，数据包有生存时间（TTL），每经过一次转发，TTL-1。这可以避免数据包无法传送到目标主机导致网络风暴。在这里我们需要丢弃所有TTL<=0的包。

##### 1.4 校验和

```cpp
unsigned short get_checksum(unsigned short int* pBuffer, int length){
	// play with memory is always problematic
	unsigned int checksum = 0;
	for(int i = 0; i < length ; i ++){
		checksum += ntohs(pBuffer[i]);
		// carry-add
		checksum = (checksum >> 16) + (checksum & 0xffff);
	}
	return checksum;
}
```

IPv4采用了一种特殊的方法处理校验和——将数据以16bit为单位切分并相加，每溢出一次，将结果+1。get_checksum函数计算一个数据包的Checksum。

```cpp
	uint16_t checksum = ntohs(ipv4Header.checksum);	
	// checksum error
	unsigned short curr_checksum = get_checksum((unsigned short *)pBuffer, headerLength*4);
	if(curr_checksum != 0xffff){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
		printf("[RECV] checksum %x, got %x\n", checksum, curr_checksum);
		return STUD_IP_TEST_CHECKSUM_ERROR;
	}
```

如果校验和正确，这里得到的checksum应为0xffff。若校验和错误，说明传输过程中出现了错误，我们需要丢弃这个数据包。

这里需要注意，TCP/IP采用大端序，而现代计算机多为小端序；因此处理长于一个字节的数据类型时，我们都要进行网络序到主机序的转换。

##### 1.5 地址

```cpp
	// address error
	// if not local addr or broadcast
	int localAddr = getIpv4Address();
	uint32_t destAddr = ntohl(ipv4Header.destAddr);
	if (destAddr != localAddr && destAddr != 0xffffffff){
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);
		printf("[RECV] local_ip %x, got %x\n", localAddr, destAddr);
		return STUD_IP_TEST_DESTINATION_ERROR;
	}
```

如果数据包目的地址是本机地址或广播地址，则会被本机接收；否则则会被丢弃。（不过抓包的设备可以不丢弃这一部分包）

```cpp	
	// send
	ip_SendtoUp((char*)&ipv4Header, length);
	printf("[RECV] send to lower\n");
	return STUD_IP_TEST_CORRECT;
}
```

调用ip_SendtoUp函数，将数据包交给系统。

#### 2. 发送接口

```cpp
int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
	unsigned short totallen = len + 20; 
    char *pSend = (char*)malloc(sizeof(char)*(totallen));

    // version headlength
    pSend[0] = 0x45;

    unsigned short hdrlen = htons(totallen);
    memcpy(pSend + 2, &hdrlen, sizeof(unsigned short));

    // time to live
    pSend[8] = ttl;

    // protocol
    pSend[9] = protocol;

    // source address
    unsigned int source_add = htonl(srcAddr);
    memcpy(pSend + 12, &source_add, sizeof(unsigned int));

    // destination address
    unsigned int dest_add = htonl(dstAddr);
    memcpy(pSend + 16, &dest_add, sizeof(unsigned int));

    // checksum
    unsigned short checksum = 0xffff - get_checksum(pSend);
    memcpy(pSend + 10, &checksum, sizeof(short));

    // data
    memcpy(pSend + 20, pBuffer, totallen);
	
	ip_SendtoLower(pSend, len+20);
	
	return STUD_IP_TEST_CORRECT;
}
```

stud_ip_Upsend完成了根据参数生成数据包再调用ip_SendtoLower的过程。

1. 这里将数据包的第一个byte硬编码为0x45（IPv4，20bytes）。
2. 参照实验指导书，这里将标识符设为固定值1926。
3. 我们可以将校验和位先初始化为0，调用同一个get_checksum算出校验和，再填入。