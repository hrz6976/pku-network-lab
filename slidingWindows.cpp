// Sliding Windows
// 12f23eddde <1800012926@pku.edu.cn> - Mar 31 2021

// - START TEMPLATE -

#include "sysinclude.h"

extern void SendFRAMEPacket(unsigned char* pData, unsigned int len);

#define WINDOW_SIZE_STOP_WAIT 1
#define WINDOW_SIZE_BACK_N_FRAME 4

typedef enum {DATA, ACK, NAK} FrameType; 

struct FrameHeader{
	FrameType type;
	unsigned int seq;
	unsigned int ack;
	unsigned char data[100];//数据
};

struct Frame {
	FrameHeader head; //帧头
	unsigned int size; //数据的大小
};

// - END TEMPLATE -

#include <queue> 
#include <deque> 
#include <cstdlib>
using namespace std;

/*
* 停等协议测试函数
*/
int stud_slide_window_stop_and_wait(char *pBuffer, int bufferSize, UINT8 messageType){
	static queue <Frame> sendList;  // 发送队列
	static bool sendNext = true; // 能否发送

	Frame f;  // Netriver的远古编译器对语法有些神秘限制

	printf("[STOPWAIT] bufferSize=%d, messageType=%d\n");
	switch (messageType){
	case MSG_TYPE_SEND:
		// 先把帧存进队列
		memcpy(&f, pBuffer, bufferSize);
		f.size = bufferSize;
		sendList.push(f);
		printf("[STOPWAIT] SEND push packet\n");

		if(sendNext){ // 可以发送包
			// 发送队首包
			f = sendList.front();
			SendFRAMEPacket((unsigned char *)(&f), (unsigned int)f.size);
			sendNext = false; // 在ACK前不发送
			printf("[STOPWAIT] SEND send packet");
		}
		break;
	case MSG_TYPE_RECEIVE:
		sendList.pop();  // 移除已经发送的帧
		sendNext = true;  // 可以继续发送帧
		
		if(!sendList.empty()){  // 如果队列里有帧，在这里发送
			f = sendList.front();
			SendFRAMEPacket((unsigned char *)&f, (unsigned int)f.size);
			sendNext = false; // 在ACK前不发送
			printf("[STOPWAIT] RECEIVE send packet");
		}
		break;
	case MSG_TYPE_TIMEOUT:
		// 发送队首包
		f = sendList.front();
		SendFRAMEPacket((unsigned char *)&f, (unsigned int)f.size);
		sendNext = false; // 在ACK前不发送
		printf("[STOPWAIT] TIMEOUT send packet\n");
		break;
	default:
		printf("[STOPWAIT] message type not specfied: %d\n", messageType);
		break;
	}
	return 0;
}

/*
* 回退n帧测试函数
*/
int stud_slide_window_back_n_frame(char *pBuffer, int bufferSize, UINT8 messageType)
{
	static deque <Frame> sendList;  // 发送队列

	Frame f;  // Netriver的远古编译器对语法有些神秘限制
	int ackedFrameSeq;
	int pop_count;

	printf("[STOPWAIT] bufferSize=%d, messageType=%d\n");
	switch (messageType){
	case MSG_TYPE_SEND:
		// 先把帧存进队列
		memcpy(&f, pBuffer, bufferSize);
		f.size = bufferSize;
		sendList.push_back(f);
		printf("[STOPWAIT] SEND push packet seq=%d\n", ntohl(f.head.seq));

		if(sendList.size() <= WINDOW_SIZE_BACK_N_FRAME){  // 窗口没有满
			// 可以发送包			
			SendFRAMEPacket((unsigned char *)(&f), (unsigned int)f.size);
			printf("[STOPWAIT] SEND send packet seq=%d\n", ntohl(f.head.seq));
		}
		break;

	case MSG_TYPE_RECEIVE:
		memcpy(&f, pBuffer, bufferSize);
		ackedFrameSeq = ntohl(f.head.ack);
		pop_count = 0;
		while(!sendList.empty() && ntohl(sendList.front().head.seq) <= ackedFrameSeq){
			sendList.pop_front();  // 移除已经发送的帧
			pop_count += 1;
		}
		while(!sendList.empty() && pop_count){
			// sendList: * | * | 4-2 | 4-1 |
			f = sendList[WINDOW_SIZE_BACK_N_FRAME - pop_count];
			pop_count -= 1;
			SendFRAMEPacket((unsigned char *)&f, (unsigned int)f.size);
			printf("[STOPWAIT] RECEIVE send packet seq=%d\n", ntohl(f.head.seq));
		}
		break;

	case MSG_TYPE_TIMEOUT:
		// 发送窗口内所有的帧
		for(int i = 0; i < WINDOW_SIZE_BACK_N_FRAME; i++){
			f = sendList[i];
			SendFRAMEPacket((unsigned char *)&f, (unsigned int)f.size);
			printf("[STOPWAIT] TIMEOUT send packet seq=%d\n", ntohl(f.head.seq));
		}
		break;
		
	default:
		printf("[STOPWAIT] message type not specfied: %d\n", messageType);
		break;
	}
	return 0;
}

/*
* 选择性重传测试函数
*/
int stud_slide_window_choice_frame_resend(char *pBuffer, int bufferSize, UINT8 messageType)
{
	static deque <Frame> sendList;  // 发送队列

	Frame f;  // Netriver的远古编译器对语法有些神秘限制
	int ackedFrameSeq;
	int pop_count;
	FrameType type;

	printf("[STOPWAIT] bufferSize=%d, messageType=%d\n");
	switch (messageType){
	case MSG_TYPE_SEND:
		// 先把帧存进队列
		memcpy(&f, pBuffer, bufferSize);
		f.size = bufferSize;
		sendList.push_back(f);
		printf("[STOPWAIT] SEND push packet seq=%d\n", ntohl(f.head.seq));

		if(sendList.size() <= WINDOW_SIZE_BACK_N_FRAME){  // 窗口没有满
			// 可以发送包			
			SendFRAMEPacket((unsigned char *)(&f), (unsigned int)f.size);
			printf("[STOPWAIT] SEND send packet seq=%d\n", ntohl(f.head.seq));
		}
		break;

	case MSG_TYPE_RECEIVE:
		memcpy(&f, pBuffer, bufferSize);
		ackedFrameSeq = ntohl(f.head.ack);
		type = (FrameType) ntohl(f.head.type);
		
		if(type == ACK){
			pop_count = 0;
			while(!sendList.empty() && ntohl(sendList.front().head.seq) <= ackedFrameSeq){
				sendList.pop_front();  // 移除已经发送的帧
				pop_count += 1;
			}
			while(!sendList.empty() && pop_count){
				// sendList: * | * | 4-2 | 4-1 |
				f = sendList[WINDOW_SIZE_BACK_N_FRAME - pop_count];
				pop_count -= 1;
				SendFRAMEPacket((unsigned char *)&f, (unsigned int)f.size);
				printf("[STOPWAIT] RECEIVE send packet seq=%d\n", ntohl(f.head.seq));
			}
		} else {
			// 选择重传
			for(int i = 0; i < sendList.size(); i++){
				if(ntohl(sendList[i].head.seq) == ackedFrameSeq){
					f = sendList[i];
					SendFRAMEPacket((unsigned char *)&f, (unsigned int)f.size);
					printf("[STOPWAIT] RECEIVE send packet seq=%d\n", ntohl(f.head.seq));
				}
			}
		}
		break;
	case MSG_TYPE_TIMEOUT:
		// 发送窗口内所有的帧
		for(int i = 0; i < WINDOW_SIZE_BACK_N_FRAME; i++){
			f = sendList[i];
			SendFRAMEPacket((unsigned char *)&f, (unsigned int)f.size);
			printf("[STOPWAIT] TIMEOUT send packet seq=%d\n", ntohl(f.head.seq));
		}
		break;
	default:
		printf("[STOPWAIT] message type not specfied: %d\n", messageType);
		break;
	}
	return 0;
}
