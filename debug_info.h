#ifndef DEBUG_INFO_H
#define DEBUG_INFO_H

#include "dns_msg.h"

// ���������Ϣ
void debug(Dns_Msg* msg);

// ���resource record
void RRInfo(Dns_RR* rr);

// ���16�����ֽ���
void bytestreamInfo(unsigned char* bytestream);

// ��ӡ����ִ��ʱ��
void printTime();

#endif // DEBUG_INFO_H#pragma once
