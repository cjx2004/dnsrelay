#include "output.h"
#include <stdio.h>
#include "msg_convert.h"
#include <time.h>

#include "output.h"
#include <stdio.h>
#include "msg_convert.h"
#include <time.h>

/*
* RRInfo(Dns_RR* rr): 输出单个资源记录（Resource Record，RR）的详细信息。根据记录类型（IPv4或IPv6）输出不同格式的数据字段。
*
* debug(Dns_Msg* msg): 输出调试信息，打印整个 DNS 报文的各个部分信息，包括报文头部、问题部分、应答部分、授权部分和附加部分。调用了前面的 printTime() 和 RRInfo() 函数。
*
* bytestreamInfo(unsigned char* bytestream): 输出字节流的16进制表示。将字节流转换为 DNS 消息结构体后，按16进制格式输出字节流内容，并释放相关内存。
*/



// 输出调试信息，打印DNS报文的各个部分
void debug(Dns_Msg* msg)
{


    // 打印报文头部信息
    printf("------------------------头部------------------------\n");
    printf("ID:%2d  ", msg->header->id);
    printf("响应标志:%2d  ", msg->header->qr);
    printf("操作码:%2d  ", msg->header->opcode);
    printf("授权回答:%2d  ", msg->header->aa);
    printf("可截断:%2d  ", msg->header->tc);
    printf("递归请求:%2d  ", msg->header->rd);
    printf("递归可用:%2d\n", msg->header->ra);
    printf("响应码:%2d  ", msg->header->rcode);
    printf("问题数:%2d  ", msg->header->qdcount);
    printf("回答数:%2d  ", msg->header->ancount);
    printf("授权数:%2d  ", msg->header->nscount);
    printf("附加数:%2d\n", msg->header->arcount);

    // 打印问题部分信息
    Dns_Question* current_que = msg->question;
    printf("-----------------------问题-----------------------\n");
    for (int i = 0; i < msg->header->qdcount; i++)
    {
        printf("问题 %d\n", i + 1);
        unsigned char name[512];
        transDN(current_que->qname, name); // 转换域名格式
        printf("域名:%20s  ", name);
        printf("类型:%2d  ", current_que->qtype);
        printf("类别:%2d\n", current_que->qclass);
        current_que = current_que->next;
    }

    // 打印回答部分信息
    Dns_RR* rr = msg->RRs;
    if (msg->header->ancount)
    {
        printf("------------------------回答------------------------\n");
    }
    for (int i = 0; i < msg->header->ancount; i++)
    {
        printf("资源记录 %d\n", i + 1);
        RRInfo(rr); // 输出单个资源记录的信息
        rr = rr->next;
    }

    // 打印授权部分信息
    if (msg->header->nscount)
    {
        printf("-----------------------授权----------------------\n");
    }
    for (int i = 0; i < msg->header->nscount; i++)
    {
        printf("资源记录 %d\n", i + 1);
        RRInfo(rr); // 输出单个资源记录的信息
        rr = rr->next;
    }

    // 打印附加信息部分信息
    if (msg->header->arcount)
    {
        printf("----------------------附加----------------------\n");
    }
    for (int i = 0; i < msg->header->arcount; i++)
    {
        printf("资源记录 %d\n", i + 1);
        RRInfo(rr); // 输出单个资源记录的信息
        rr = rr->next;
    }

    printf("------------------------------------------------------\n");
}

// 输出字节流的16进制表示
void bytestreamInfo(unsigned char* bytestream)
{
    unsigned short offset;
    Dns_Msg* msg = bytestream_to_dnsmsg(bytestream, &offset); // 将字节流转换为DNS消息结构体
    for (int i = 0; i < (int)(offset); i += 16)
    {
        printf("%04lx: ", i); // 输出偏移地址
        for (int j = i; j < i + 16 && j < (int)(offset); j++)
        {
            printf("%02x ", (unsigned char)bytestream[j]); // 输出16进制表示的字节
        }
        printf("\n");
    }
    releaseMsg(msg); // 释放DNS消息结构体内存
}

// 输出单个Resource Record的信息
void RRInfo(Dns_RR* rr)
{
    unsigned char name[UDP_MAX];
    transDN(rr->name, name); // 转换域名格式
    printf("名称:%20s  ", name);
    printf("类型:%2d  ", rr->type);
    printf("类别:%2d\n", rr->_class);
    printf("生存时间:%2d  ", rr->ttl);
    printf("数据长度:%2d  ", rr->rdlength);

    // 根据记录类型输出不同格式的数据字段
    if (rr->type == TYPE_A)
    {
        unsigned char IPv4[20];
        transIPv4(rr->rdata, IPv4); // 转换IPv4地址格式
        printf("数据内容:%20s", IPv4);
    }
    else if (rr->type == TYPE_AAAA)
    {
        unsigned char IPv6[40];
        transIPv6(rr->rdata, IPv6); // 转换IPv6地址格式
        printf("数据内容:%20s", IPv6);
    }
    printf("\n");
}