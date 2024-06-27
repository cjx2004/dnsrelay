#ifndef OUTPUT_H
#define OUTPUT_H

#include "dns_msg.h"

/*
*RRInfo(Dns_RR rr)**: 输出单个资源记录（Resource Record，RR）的详细信息。根据记录类型（IPv4或IPv6）输出不同格式的数据字段。

*debug(Dns_Msg msg)**: 输出调试信息，打印整个 DNS 报文的各个部分信息，包括报文头部、问题部分、应答部分、授权部分和附加部分。调用了前面的 printTime() 和 RRInfo() 函数。

*bytestreamInfo(unsigned char bytestream)**: 输出字节流的16进制表示。将字节流转换为 DNS 消息结构体后，按16进制格式输出字节流内容，并释放相关内存。
*/

// 输出调试信息
void debug(Dns_Msg* msg);

// 输出resource record
void RRInfo(Dns_RR* rr);

// 输出16进制字节流
void bytestreamInfo(unsigned char* bytestream);


#endif // OUTPUT_H#pragma once
