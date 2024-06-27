#include "msg_convert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <Winsock2.h>
#include <windows.h>
// Windows-specific code
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// Linux-specific code
#endif

#pragma comment(lib, "ws2_32.lib")

// 从字节流中提取出header的内容
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

// 解析字节流中的DNS报文头部，并填充到Dns_Header结构体中
void getHeader(Dns_Header* header, const unsigned char* bytestream)
{
    // 从字节流中提取并转换DNS报文头部字段
    header->id = ntohs(*(unsigned short*)bytestream); // 报文ID，使用ntohs将网络字节顺序转换为主机字节顺序
    header->qr = (bytestream[2] >> 7) & 1; // 查询/响应标志位
    header->opcode = (bytestream[2] >> 3) & 0x0f; // 操作码
    header->aa = (bytestream[2] >> 2) & 1; // 授权回答标志
    header->tc = (bytestream[2] >> 1) & 1; // 截断标志
    header->rd = (bytestream[2]) & 1; // 递归查询标志
    header->ra = (bytestream[3] >> 7) & 1; // 可用性标志
    header->z = (bytestream[3] >> 4) & 0x07; // 保留字段，必须为0
    header->rcode = (bytestream[3]) & 0x0f; // 响应码
    header->qdcount = ntohs(*(unsigned short*)(bytestream + 4)); // 问题区域记录数
    header->ancount = ntohs(*(unsigned short*)(bytestream + 6)); // 回答区域记录数
    header->nscount = ntohs(*(unsigned short*)(bytestream + 8)); // 授权区域记录数
    header->arcount = ntohs(*(unsigned short*)(bytestream + 10)); // 附加区域记录数
}

// 从字节流中提取域名，并存储到指定的qname数组中，同时更新offset表示的偏移量
void getName(unsigned char* qname, const unsigned char* bytestream, unsigned short* offset)
{
    while (*(bytestream + *offset) != 0) // 每个标签以0结束，当遇到0时表示域名结束
    {
        if (((*(bytestream + *offset) >> 6) & 3) == 3) // 判断是否为压缩标签
        {
            unsigned short new_offset = ntohs(*(unsigned short*)(bytestream + *offset)) & 0x3fff; // 获取新的偏移量
            getName(qname, bytestream, &new_offset); // 递归处理压缩的域名
            (*offset) += 2; // 更新偏移量，跳过压缩标签的2个字节
            return;
        }
        *qname = *(bytestream + *offset); // 将当前字节作为域名的一部分存入qname数组
        qname++; // 指向下一个位置
        (*offset)++; // 更新偏移量，指向下一个字节
    }
    (*offset)++; // 跳过末尾的0字节
    *qname = '\0'; // 添加字符串结束标志
}


// 从字节流中提取出question的内容
/*
       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

// 从字节流中提取DNS查询部分的问题信息，并填充到Dns_Question结构体中
void getQuestion(Dns_Question* question, const unsigned char* bytestream, unsigned short* offset)
{
    // 动态分配内存存储问题的域名
    question->qname = (unsigned char*)malloc(sizeof(unsigned char) * UDP_MAX);
    if (!question->qname)
    {
        puts("动态分配内存失败"); // 内存分配失败提示
        exit(1); // 退出程序，处理内存分配失败的情况
    }

    // 提取域名信息，并存储到question->qname中，同时更新offset
    getName(question->qname, bytestream, offset);

    // 提取问题类型（qtype）和问题类（qclass），并转换为主机字节顺序
    question->qtype = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // 更新offset，跳过问题类型字段

    question->qclass = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // 更新offset，跳过问题类字段
}


// 从字节流中提取RR的内容
/*
                                     1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */

// 从字节流中提取DNS资源记录（Resource Record）信息，并填充到Dns_RR结构体中
void getRR(Dns_RR* RR, const unsigned char* bytestream, unsigned short* offset)
{
    // 动态分配内存存储资源记录的域名
    RR->name = (unsigned char*)malloc(sizeof(unsigned char) * UDP_MAX);
    if (!RR->name)
    {
        puts("动态分配内存失败"); // 内存分配失败提示
        exit(1); // 退出程序，处理内存分配失败的情况
    }

    // 提取域名信息，并存储到RR->name中，同时更新offset
    getName(RR->name, bytestream, offset);

    // 提取资源记录的类型（type）、类（class）、TTL和数据长度（rdlength），并转换为主机字节顺序
    RR->type = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // 更新offset，跳过类型字段

    RR->_class = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // 更新offset，跳过类字段

    RR->ttl = ntohl(*(unsigned int*)(bytestream + *offset));
    (*offset) += 4; // 更新offset，跳过TTL字段

    RR->rdlength = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // 更新offset，跳过数据长度字段

    // 动态分配内存存储资源记录的数据（rdata），根据rdlength复制相应长度的字节流，并添加字符串结尾
    RR->rdata = (unsigned char*)malloc(sizeof(unsigned char) * RR->rdlength + 1);
    if (!RR->rdata)
    {
        puts("动态分配内存失败"); // 内存分配失败提示
        exit(1); // 退出程序，处理内存分配失败的情况
    }
    memcpy(RR->rdata, bytestream + *offset, RR->rdlength);
    RR->rdata[RR->rdlength] = '\0'; // 添加字符串结尾
    (*offset) += RR->rdlength; // 更新offset，跳过数据字段
}

// 将原始的IPv4地址转换为点分十进制形式的字符串表示
void transIPv4(unsigned char* original, unsigned char* IPv4)
{
    // 使用sprintf将原始的IPv4地址转换为字符串格式
    sprintf((char*)(IPv4), "%d.%d.%d.%d", original[0], original[1], original[2], original[3]);
}

// 将原始的IPv6地址转换为冒分十六进制形式的字符串表示
void transIPv6(unsigned char* original, unsigned char* IPv6)
{
    // 使用sprintf将原始的IPv6地址转换为冒分十六进制形式的字符串格式
    sprintf((char*)(IPv6), "%x:%x:%x:%x:%x:%x:%x:%x", ntohs(*(unsigned short*)(original)),
        ntohs(*(unsigned short*)(original + 2)), ntohs(*(unsigned short*)(original + 4)),
        ntohs(*(unsigned short*)(original + 6)), ntohs(*(unsigned short*)(original + 8)),
        ntohs(*(unsigned short*)(original + 10)), ntohs(*(unsigned short*)(original + 12)),
        ntohs(*(unsigned short*)(original + 14)));
}

// 将原始的DNS域名格式转换为点分形式的字符串表示
void transDN(unsigned char* original, unsigned char* DN)
{
    while (*original != 0)
    {
        unsigned short len = *original; // 域名段的长度
        original++;
        memcpy(DN, original, len); // 复制域名段到目标字符串中
        original += len; // 移动原始域名指针
        DN += len; // 移动目标字符串指针
        *DN = '.'; // 添加点分隔符
        DN++;
    }
    *(DN - 1) = '\0'; // 将最后一个点改为字符串结束符
}

// 释放DNS消息结构体及其内存
void releaseMsg(Dns_Msg* msg)
{
    if (!msg)
        return;

    // 释放header部分内存
    free(msg->header);

    // 释放question部分内存
    Dns_Question* pQue = msg->question;
    while (pQue)
    {
        if (pQue->qname)
            free(pQue->qname);
        Dns_Question* temp = pQue;
        pQue = pQue->next;
        free(temp);
    }

    // 释放RRs（资源记录）部分内存
    Dns_RR* pRR = msg->RRs;
    while (pRR)
    {
        if (pRR->name)
            free(pRR->name);
        if (pRR->rdata)
            free(pRR->rdata);
        Dns_RR* temp = pRR;
        pRR = pRR->next;
        free(temp);
    }

    // 释放DNS消息结构体本身的内存
    free(msg);
}


// 将字节流转换为DNS消息结构体
Dns_Msg* bytestream_to_dnsmsg(const unsigned char* bytestream, unsigned short* offset)
{
    Dns_Msg* msg = (Dns_Msg*)malloc(sizeof(Dns_Msg));
    if (!msg)
    {
        puts("动态分配内存失败"); // 内存分配失败提示
        exit(1); // 退出程序，处理内存分配失败的情况
    }

    // 转换header部分：动态分配内存存储header，调用getHeader函数填充header信息
    msg->header = (Dns_Header*)malloc(sizeof(Dns_Header));
    if (!msg->header)
    {
        puts("动态分配内存失败"); // 内存分配失败提示
        exit(1); // 退出程序，处理内存分配失败的情况
    }
    getHeader(msg->header, bytestream); // 填充header信息

    *offset = 12; // 设置初始偏移量为12，跳过header部分

    // 转换question部分：遍历每个question并转换为Dns_Question结构体
    msg->question = NULL;
    Dns_Question* question_tail = NULL;
    for (int i = 0; i < msg->header->qdcount; i++)
    {
        Dns_Question* current = (Dns_Question*)malloc(sizeof(Dns_Question));
        if (!current)
        {
            puts("动态分配内存失败"); // 内存分配失败提示
            exit(1); // 退出程序，处理内存分配失败的情况
        }
        if (!question_tail)
        {
            msg->question = current;
            current->next = NULL;
        }
        else
        {
            question_tail->next = current;
            current->next = NULL;
        }
        question_tail = current;
        getQuestion(current, bytestream, offset); // 填充当前question信息
    }

    // 转换answer、authority、additional部分：遍历每个资源记录并转换为Dns_RR结构体
    unsigned short total_length = msg->header->ancount + msg->header->nscount + msg->header->arcount;
    msg->RRs = NULL;
    Dns_RR* RRs_tail = NULL;
    for (int i = 0; i < total_length; i++)
    {
        Dns_RR* current = (Dns_RR*)malloc(sizeof(Dns_RR));
        if (!current)
        {
            puts("动态分配内存失败"); // 内存分配失败提示
            exit(1); // 退出程序，处理内存分配失败的情况
        }
        if (!RRs_tail)
        {
            msg->RRs = current;
            current->next = NULL;
        }
        else
        {
            RRs_tail->next = current;
            current->next = NULL;
        }
        RRs_tail = current;
        getRR(current, bytestream, offset); // 填充当前资源记录信息
    }

    return msg; // 返回填充完整的DNS消息结构体
}


// 将DNS消息结构体中的header部分填入字节流
void putHeader(const Dns_Header* header, unsigned char* bytestream)
{
    // 填入16位的id字段，高8位在前，低8位在后
    bytestream[0] = header->id >> 8;
    bytestream[1] = header->id;

    // 填入8位的标志位字段
    bytestream[2] = 0;
    bytestream[2] |= header->qr << 7;      // QR标志位，1位
    bytestream[2] |= header->opcode << 3;  // 操作码，4位
    bytestream[2] |= header->aa << 2;      // 授权答案标志位，1位
    bytestream[2] |= header->tc << 1;      // 截断标志位，1位
    bytestream[2] |= header->rd;           // 期望递归标志位，1位

    // 填入8位的响应码字段
    bytestream[3] = 0;
    bytestream[3] |= header->ra << 7;      // 可用性标志位，1位
    bytestream[3] |= header->z << 4;       // 保留字段，3位
    bytestream[3] |= header->rcode;        // 响应码，4位

    // 填入16位的问题数字段
    bytestream[4] = header->qdcount >> 8;
    bytestream[5] = header->qdcount;

    // 填入16位的回答数字段
    bytestream[6] = header->ancount >> 8;
    bytestream[7] = header->ancount;

    // 填入16位的授权记录数字段
    bytestream[8] = header->nscount >> 8;
    bytestream[9] = header->nscount;

    // 填入16位的附加记录数字段
    bytestream[10] = header->arcount >> 8;
    bytestream[11] = header->arcount;
}

// 将DNS消息结构体中的question部分填入字节流
void putQuestion(const Dns_Question* question, unsigned char* bytestream, unsigned short* offset)
{
    // 复制域名字段到字节流中，直到遇到域名结束符0
    memcpy(bytestream + *offset, question->qname, strlen((char*)(question->qname)) + 1);
    *offset += strlen((char*)(question->qname)) + 1;

    // 填入16位的问题类型字段
    *(bytestream + *offset) = question->qtype >> 8;
    (*offset)++;

    *(bytestream + *offset) = question->qtype;
    (*offset)++;

    // 填入16位的问题类字段
    *(bytestream + *offset) = question->qclass >> 8;
    (*offset)++;

    *(bytestream + *offset) = question->qclass;
    (*offset)++;
}

// 将DNS消息结构体中的RR（资源记录）部分填入字节流
void putRR(const Dns_RR* rr, unsigned char* bytestream, unsigned short* offset)
{
    // 复制域名字段到字节流中，直到遇到域名结束符0
    memcpy(bytestream + *offset, rr->name, strlen((char*)(rr->name)) + 1);
    *offset += strlen((char*)(rr->name)) + 1;

    // 填入16位的类型字段
    *(bytestream + *offset) = rr->type >> 8;
    (*offset)++;

    *(bytestream + *offset) = rr->type;
    (*offset)++;

    // 填入16位的类字段
    *(bytestream + *offset) = rr->_class >> 8;
    (*offset)++;

    *(bytestream + *offset) = rr->_class;
    (*offset)++;

    // 填入32位的TTL字段
    *(bytestream + *offset) = rr->ttl >> 24;
    (*offset)++;

    *(bytestream + *offset) = rr->ttl >> 16;
    (*offset)++;

    *(bytestream + *offset) = rr->ttl >> 8;
    (*offset)++;

    *(bytestream + *offset) = rr->ttl;
    (*offset)++;

    // 填入16位的数据长度字段
    *(bytestream + *offset) = rr->rdlength >> 8;
    (*offset)++;

    *(bytestream + *offset) = rr->rdlength;
    (*offset)++;

    // 复制rdata字段到字节流中
    memcpy(bytestream + *offset, rr->rdata, rr->rdlength);
    *offset += rr->rdlength;
}

// 将DNS消息结构体转换为字节流表示
unsigned char* dnsmsg_to_bytestream(const Dns_Msg* msg)
{
    unsigned char* bytestream = (unsigned char*)malloc(sizeof(unsigned char) * UDP_MAX);
    if (!bytestream)
    {
        puts("动态分配内存失败"); // 内存分配失败提示
        exit(1); // 退出程序，处理内存分配失败的情况
    }

    // 填入header部分到字节流中
    putHeader(msg->header, bytestream);

    // 设置初始偏移量为12，用于跳过header部分
    unsigned short offset = 12;

    // 填入question部分到字节流中
    Dns_Question* question = msg->question;
    while (question)
    {
        putQuestion(question, bytestream, &offset);
        question = question->next;
    }

    // 填入answer、authority、additional部分到字节流中
    Dns_RR* rr = msg->RRs;
    while (rr)
    {
        putRR(rr, bytestream, &offset);
        rr = rr->next;
    }

    return bytestream;
}
