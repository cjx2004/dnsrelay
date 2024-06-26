#pragma once
#ifndef DNS_FUNCTION_H
#define DNS_FUNCTION_H

#include "dns_msg.h"

// ���answer�ֶ�
void addAnswer(Dns_Msg* msg, const unsigned char* IP, unsigned int _ttl, unsigned short _type);

// ���ⲿDNS�Ļظ���������ȡ������IP��ַ
void getDN_IP(const unsigned char* bytestream, unsigned char* DN, unsigned char* IP, unsigned int* _ttl, unsigned short* _type);

#endif // DNS_FUNCTION_H