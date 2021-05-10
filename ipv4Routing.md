##### 1.  初始化路由表

这里我们采用STL中的vector来维护路由表。vector能实现动态内存分配，并且有不错的遍历性能；数据类型则直接实验提供的stud_route_msg。


```cpp
// use vector to allocate memory automatically
vector <struct stud_route_msg> routeTable;

void stud_Route_Init(){
	return;
}
```

##### 2. 在路由表中添加项

将参数中的项添加到路由表的向量中。这里需要注意，`proute`中的所有变量均采用大端序（这一点实验指导书没有给出）。

```cpp
void stud_route_add(stud_route_msg *proute){
	routeTable.push_back(*proute);
	printf("masklen=%d nexthop=%x\n", ntohl(proute->masklen), ntohl(proute->nexthop));
	return;
}
```

##### 3. 转发包

以下代码获取一个IP包头的校验和（校验和位不会纳入计算）：

```cpp
uint16_t ipChecksum(char *pBuffer){
    int sum = 0;
    for(int i = 0; i < 10; ++i){
        if(i == 5) continue;
        sum += ((unsigned short*)pBuffer)[i];
    }
    while(sum > 0xffff){
        sum = (sum & 0xffff) + (sum >> 16); 
    }
    return (unsigned short)(0xffff - sum);
}
```

我们在处理之前，先使用以下代码读出IP包头中的TTL，目标地址等信息：

```cpp
int stud_fwd_deal(char *pBuffer, int length){

	// extract info from ipHeader
	IPHead ipv4Header = *(IPHead*)pBuffer;  // this is not real memory reference
	uint8_t ver = ipv4Header.ver >> 4;
	uint8_t hdrLen = ipv4Header.ver & 0xf;
	uint8_t ttl = ipv4Header.ttl;
	uint32_t destAddr = ntohl(ipv4Header.destAddr);
```

（注意修改ipv4Header并不会修改pBuffer中的值）

如果目标地址是本机地址，则转发到本机的上层协议。（`getIpv4Address()`获得的值是小端序）

```cpp
	// is local address?
	printf("[FWD] dest addr %x\n", destAddr);
	if (destAddr == getIpv4Address()){
		
		fwd_LocalRcv(pBuffer, length);
		return 0;
	}
```

目标地址不是本机地址，则需要在网络中进行转发。在转发前，我们需要丢弃所有TTL<=0的包：


```cpp
	// not local address, ttl > 0
	if (ttl <= 0){
		printf("[FWD] ttl=%d\n", ttl);
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
		return 1;
	}
```

接下来，我们需要遍历路由表项，按照最长匹配原则选择与目标地址最接近的端口进行转发。如果路由表中没有与目标地址匹配的项，则丢弃数据包。

```cpp
	int best_idx = -1;
	int best_masklen = -1;
	// find best route in route table
	for(int i = 0; i < routeTable.size(); i++){
		int masklen = ntohl(routeTable[i].masklen);
		uint32_t mask = 0xffffffff << (32-masklen);
		// mask 0xfff & id
		printf("[FWD] table addr %x\n", ntohl(routeTable[i].dest));
		printf("%x %x", (ntohl(routeTable[i].dest) & mask), (destAddr & mask));
		if((ntohl(routeTable[i].dest) & mask) == (destAddr & mask)){  // match
			// find largest masklen
			if(masklen > best_masklen){
				best_idx = i;
			}
		}
	}

	printf("[FWD] idx=%d len=%d\n", best_idx, best_masklen);

	if(best_idx == -1){ // mismatch
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
		return 1;
	}
```

在网络中转发数据包前，我们需要先将TTL-1，并重新计算校验和（直接赋值会造成大小端错误，因此这里直接`memcpy`）。最后，想下一跳路由发送包。


```cpp
	// ttl-1
	pBuffer[8] -= 1;

	// redo checksum
	unsigned short localCheckSum = ipChecksum(pBuffer);
	memcpy(pBuffer+10, &localCheckSum, sizeof(unsigned short));
	
	// send packet
	fwd_SendtoLower(pBuffer, length, routeTable[best_idx].nexthop);

	return 0;
}
```

