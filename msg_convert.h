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


// 字节流转换为DNS报文结构体
Dns_Msg * btod(const unsigned char* bytestream, unsigned short* offset);

// DNS报文结构体转换为字节流
unsigned char* dtob(const Dns_Msg* msg);

// 从字节流中提取Header的内容
void getHeader(Dns_Header* header, const unsigned char* bytestream);

// 获取域名
void getName(unsigned char* qname, const unsigned char* bytestream, unsigned short* offset);

// 从字节流中提取Question的内容
void getQuestion(Dns_Question* question, const unsigned char* bytestream, unsigned short* offset);

// 从字节流中提取RR的内容
void getRR(Dns_RR* RR, const unsigned char* bytestream, unsigned short* offset);

// 将Header填入字节流
void puth(const Dns_Header* header, unsigned char* bytestream);

// 将Question填入字节流
void putQ(const Dns_Question* question, unsigned char* bytestream, unsigned short* offset);

// 将RR填入字节流
void putr(const Dns_RR* rr, unsigned char* bytestream, unsigned short* offset);

// 获得点分十进制形式的IPv4地址
void tran4(unsigned char* original, unsigned char* IPv4);

// 获得冒分十六进制形式的IPv6地址
void tran6(unsigned char* original, unsigned char* IPv6);

// 获得xx.xx.xx形式的域名
void transDN(unsigned char* original, unsigned char* DN);

// 释放DNS报文结构体
void releaseMsg(Dns_Msg* msg);

#endif // MSG_CONVERT_H

/*
* 描述了 DNS 消息的基本格式，包括消息头部（ID、QR、Opcode、AA、TC、RD、RA、Z、RCODE）、QDCOUNT、ANCOUNT、NSCOUNT 和 ARCOUNT。
每个函数的功能都在注释中简要描述，包括字节流到结构体的转换、结构体到字节流的转换、字段提取和填充等操作。
各个函数的具体实现可以在对应的源文件中找到。
*/