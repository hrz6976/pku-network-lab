// ipv4 Routing
// 12f23eddde <rzhe@pku.edu.cn> - Apr 27 2021

#include "sysInclude.h"
#include <vector>

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

extern void fwd_DiscardPkt(char *pBuffer, int type);

extern unsigned int getIpv4Address( );

// implemented by students

// use vector to allocate memory automatically
vector <struct stud_route_msg> routeTable;

void stud_Route_Init(){
	return;
}

void stud_route_add(stud_route_msg *proute){
	routeTable.push_back(*proute);
	printf("masklen=%d nexthop=%x\n", ntohl(proute->masklen), ntohl(proute->nexthop));
	return;
}

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

int stud_fwd_deal(char *pBuffer, int length){

	// extract info from ipHeader
	IPHead ipv4Header = *(IPHead*)pBuffer;  // this is not real memory reference
	uint8_t ver = ipv4Header.ver >> 4;
	uint8_t hdrLen = ipv4Header.ver & 0xf;
	uint8_t ttl = ipv4Header.ttl;
	uint32_t destAddr = ntohl(ipv4Header.destAddr);

	// is local address?
	printf("[FWD] dest addr %x\n", destAddr);
	if (destAddr == getIpv4Address()){
		
		fwd_LocalRcv(pBuffer, length);
		return 0;
	}

	// not local address, ttl > 0
	if (ttl <= 0){
		printf("[FWD] ttl=%d\n", ttl);
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
		return 1;
	}

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

	// ttl-1
	pBuffer[8] -= 1;

	// redo checksum
	unsigned short localCheckSum = ipChecksum(pBuffer);
	memcpy(pBuffer+10, &localCheckSum, sizeof(unsigned short));
	
	// send packet
	fwd_SendtoLower(pBuffer, length, routeTable[best_idx].nexthop);

	return 0;
}