#ifndef MSG_CONVERT_H
#define MSG_CONVERT_H

#include "dns_msg.h"

// �ֽ���ת��Ϊdns���Ľṹ��
Dns_Msg* bytestream_to_dnsmsg(const unsigned char* bytestream, unsigned short* offset);

// dns���Ľṹ��ת��Ϊ�ֽ���
unsigned char* dnsmsg_to_bytestream(const Dns_Msg* msg);

// ���ֽ�������ȡ��header������
void getHeader(Dns_Header* header, const unsigned char* bytestream);

// ��ȡ����
void getName(unsigned char* qname, const unsigned char* bytestream, unsigned short* offset);

// ���ֽ�������ȡ��question������
void getQuestion(Dns_Question* quesiton, const unsigned char* bytestream, unsigned short* offset);

// ���ֽ�������ȡRR������
void getRR(Dns_RR* RR, const unsigned char* bytestream, unsigned short* offset);

// ��header�����ֽ���
void putHeader(const Dns_Header* header, unsigned char* bytestream);

// ��question�����ֽ���
void putQuestion(const Dns_Question* que, unsigned char* bytestream, unsigned short* offset);

// ��RR�����ֽ���
void putRR(const Dns_RR* rr, unsigned char* bytestream, unsigned short* offset);

// ��õ��ʮ������ʽ��IPv4��ַ
void transIPv4(unsigned char* original, unsigned char* IPv4);

// ���ð��ʮ��������ʽ��IPv6��ַ
void transIPv6(unsigned char* original, unsigned char* IPv6);

// ���xx.xx.xx��ʽ������
void transDN(unsigned char* original, unsigned char* DN);

// �ͷ�dns���Ľṹ��
void releaseMsg(Dns_Msg* msg);

#endif // MSG_CONVERT_H