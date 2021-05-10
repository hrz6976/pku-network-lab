// ipv4 Send & Recv
// 12f23eddde <rzhe@pku.edu.cn> - Apr 26 2021

#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

// implemented by students

// calculate checksum using carry-add (16bit)
// only checksum head
unsigned short get_checksum(unsigned short int* pBuffer){
	// play with memory is always problematic
	unsigned int checksum = 0;
	for(int i = 0; i < 10; i ++){
		checksum += ntohs(pBuffer[i]);
		// carry-add
		checksum = (checksum >> 16) + (checksum & 0xffff);
	}
	return checksum;
}

int stud_ip_recv(char *pBuffer,unsigned short length){
	struct IPHead ipv4Header;
	memcpy(&ipv4Header, pBuffer, sizeof(struct IPHead));

	// you don't need to convert byte
	// 4 bit version & headerLength (x4->bytes)
	uint8_t version = ipv4Header.ver >> 4;
	uint8_t headerLength = ipv4Header.ver & 0xf;
	uint8_t ttl = ipv4Header.ttl;
	uint16_t checksum = ntohs(ipv4Header.checksum);
	uint32_t destAddr = ntohl(ipv4Header.destAddr);

	int localAddr = getIpv4Address();

	printf("[RECV] ver=%d len=%d ttl=%d chksum=%x\n", version, headerLength, ttl, checksum);

	// version error
	if(version != 4){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
		printf("[RECV] ver!=4\n");
		return STUD_IP_TEST_VERSION_ERROR;
	}

	// header length error
	if(headerLength <= 4){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
		printf("[RECV] len<=4\n");
		return STUD_IP_TEST_HEADLEN_ERROR;
	}

	// ttl error
	if (ttl <= 0){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
		printf("[RECV] ttl<=0\n");
		return STUD_IP_TEST_TTL_ERROR;
	}

	// checksum error
	unsigned short curr_checksum = get_checksum((unsigned short *)pBuffer, headerLength*4);
	if(curr_checksum != 0xffff){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
		printf("[RECV] checksum %x, got %x\n", checksum, curr_checksum);
		return STUD_IP_TEST_CHECKSUM_ERROR;
	}

	// address error
	// if not local addr or broadcast
	if (destAddr != localAddr && destAddr != 0xffffffff){
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);
		printf("[RECV] local_ip %x, got %x\n", localAddr, destAddr);
		return STUD_IP_TEST_DESTINATION_ERROR;
	}
	
	// send
	ip_SendtoUp((char*)&ipv4Header, length);
	printf("[RECV] send to lower\n");
	return STUD_IP_TEST_CORRECT;
}


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