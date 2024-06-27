#pragma once
#ifndef MSG_CONDUCT_H
#define MSG_CONDUCT_H

#include "dns_msg.h"

// 添加answer字段
void addAnswer(Dns_Msg* msg, const unsigned char* IP, unsigned int _ttl, unsigned short _type);

// 从外部DNS的回复报文中提取域名和IP地址
void getDN_IP(const unsigned char* bytestream, unsigned char* DN, unsigned char* IP, unsigned int* _ttl, unsigned short* _type);

#endif // MSG_CONDUCT_H