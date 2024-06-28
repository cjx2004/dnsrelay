#ifndef MSG_CONVERT_H
#define MSG_CONVERT_H

#include "dns_msg.h"
/*
    *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
//+-- + -- + -- + -- + -- + -- + -- + -- + -- + -- + -- + -- + -- + -- + -- + -- +


// �ֽ���ת��ΪDNS���Ľṹ��
Dns_Msg * btod(const unsigned char* bytestream, unsigned short* offset);

// DNS���Ľṹ��ת��Ϊ�ֽ���
unsigned char* dtob(const Dns_Msg* msg);

// ���ֽ�������ȡHeader������
void getHeader(Dns_Header* header, const unsigned char* bytestream);

// ��ȡ����
void getName(unsigned char* qname, const unsigned char* bytestream, unsigned short* offset);

// ���ֽ�������ȡQuestion������
void getQuestion(Dns_Question* question, const unsigned char* bytestream, unsigned short* offset);

// ���ֽ�������ȡRR������
void getRR(Dns_RR* RR, const unsigned char* bytestream, unsigned short* offset);

// ��Header�����ֽ���
void puth(const Dns_Header* header, unsigned char* bytestream);

// ��Question�����ֽ���
void putQ(const Dns_Question* question, unsigned char* bytestream, unsigned short* offset);

// ��RR�����ֽ���
void putr(const Dns_RR* rr, unsigned char* bytestream, unsigned short* offset);

// ��õ��ʮ������ʽ��IPv4��ַ
void tran4(unsigned char* original, unsigned char* IPv4);

// ���ð��ʮ��������ʽ��IPv6��ַ
void tran6(unsigned char* original, unsigned char* IPv6);

// ���xx.xx.xx��ʽ������
void transDN(unsigned char* original, unsigned char* DN);

// �ͷ�DNS���Ľṹ��
void releaseMsg(Dns_Msg* msg);

#endif // MSG_CONVERT_H

/*
* ������ DNS ��Ϣ�Ļ�����ʽ��������Ϣͷ����ID��QR��Opcode��AA��TC��RD��RA��Z��RCODE����QDCOUNT��ANCOUNT��NSCOUNT �� ARCOUNT��
ÿ�������Ĺ��ܶ���ע���м�Ҫ�����������ֽ������ṹ���ת�����ṹ�嵽�ֽ�����ת�����ֶ���ȡ�����Ȳ�����
���������ľ���ʵ�ֿ����ڶ�Ӧ��Դ�ļ����ҵ���
*/