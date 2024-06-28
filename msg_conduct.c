//两个函数结合起来实现了DNS中继服务器中处理和构建DNS消息的核心功能。

#include "msg_conduct.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "msg_convert.h"

/*
作用: 将一个Resource Record（资源记录）添加到DNS消息的answer字段中。这个函数主要用于构建DNS响应报文中的answer部分，响应客户端的DNS查询。
*/

// 添加一个Resource Record到DNS消息的answer字段中
void addAnswer(Dns_Msg* msg, const unsigned char* IP, unsigned int _ttl, unsigned short _type)
{
    // 不良网站拦截：如果是IPv4或IPv6类型的响应，且IP地址为0.0.0.0或全0，设置响应码为3
    if ((_type == TYPE_A || _type == TYPE_AAAA) && *(unsigned int*)(IP) == 0)
    {
        msg->header->rcode = 3;
    }
    // 设置header字段的值：响应标志qr为1（响应消息），递归查询rd为1，可用性标志ra为1，回答计数ancount加一
    
    msg->header->ra = 1;
    msg->header->ancount++;
    msg->header->qr = 1;
    msg->header->rd = 1;

    // 添加一个Resource Record到answer字段中
    Dns_RR* rr = msg->RRs;
    Dns_RR* prev = NULL;
    while (rr)
    {
        prev = rr;
        rr = rr->next;
    }

    if (prev)
    {
        // 如果已经存在前一个RR，则动态分配一个新的RR并链接到链表尾部
        rr = (Dns_RR*)malloc(sizeof(Dns_RR));
        if (!rr)
        {
            puts("动态分配内存失败"); // 内存分配失败提示
            exit(1); // 退出程序，处理内存分配失败的情况
        }
        prev->next = rr; // 前一个RR的next指向新的RR
        rr->next = NULL; // 新的RR的next设为NULL，表示链表结尾
    }
    else
    {
        // 如果prev为空，说明当前链表中还没有RR，直接为msg的RRs字段分配内存，并设定next为NULL
        msg->RRs = (Dns_RR*)malloc(sizeof(Dns_RR));
        msg->RRs->next = NULL;
        rr = msg->RRs;
    }

    // 复制问题部分的域名到answer部分的RR的name字段
    rr->name = (unsigned char*)malloc(sizeof(unsigned char) * UDP_MAX);
    memcpy(rr->name, msg->question->qname, strlen((char*)(msg->question->qname)) + 1);

    // 设置RR的类型、类、TTL、数据长度和数据
    rr->type = _type;
    rr->_class = CLASS_IN;
    rr->ttl = _ttl;

    // 根据响应的类型（IPv4或IPv6），设置数据长度和数据
    if (_type == TYPE_A)
    {
        rr->rdlength = 4; // IPv4地址长度为4字节
    }
    else
    {
        rr->rdlength = 16; // IPv6地址长度为16字节
    }
    rr->rdata = (unsigned char*)malloc(sizeof(unsigned char) * rr->rdlength);
    memcpy(rr->rdata, IP, rr->rdlength); // 复制IP地址数据到RR的rdata字段
}


/*作用: 从外部DNS的回复报文中提取域名（DN）和IP地址，以及相关的TTL和类型信息。
功能:
将字节流形式的DNS回复报文转换为DNS消息结构体。
提取DNS消息中的问题部分的域名，并通过函数transDN进行转换。
遍历DNS消息中的RRs链表，查找类型为IPv4（TYPE_A）或IPv6（TYPE_AAAA）的Resource Record，提取第一个匹配到的IP地址和相应的TTL和类型。
释放使用的内存资源，包括释放DNS消息结构体。
备注: 这个函数用于解析和提取外部DNS服务器返回的DNS响应报文中的重要信息，以便后续处理和转发给客户端。
*/

// 从外部DNS的回复报文中提取域名和IP地址
void getDN_IP(const unsigned char* bytestream, unsigned char* DN, unsigned char* IP, unsigned int* _ttl, unsigned short* _type)
{
    unsigned short offset;
    Dns_Msg* msg = btod(bytestream, &offset);
    transDN(msg->question->qname, DN);
    Dns_RR* rr = msg->RRs;
    //取RR中类型为ipv4或者v6的第一个ip地址
    while (rr)
    {
        //if(rr->type == TYPE_A)
        //if(rr->type == TYPE_AAAA)
        if (rr->type == TYPE_A || rr->type == TYPE_AAAA)
        {
            *_type = rr->type;
            memcpy(IP, rr->rdata, rr->rdlength);
            *_ttl = rr->ttl;
            break;
        }
        rr = rr->next;
    }
    releaseMsg(msg);
}