#ifndef DNS_MSG_H
#define DNS_MSG_H

#define UDP_MAX 512

/*
·QR（1 bit）查询/响应标志，0为查询，1为响应。
·opcode（1 bit）0表示标准查询，1表示反向查询，2表示服务器转态请求。
·AA（1 bit）表示授权回答
·TC（1 bit）表示可截断的
·RD（1 bit）表示期望递归
·RA（1 bit）表示可用递归
·RCODE（4 bit）表示返回码，0表示没有差错，3表示名字差错，2表示服务器错误（Server Failure）
（3）数量字段（总共8字节）：各自表示后面的四个区域的数目。
·QDCOUNT表示question section的问题个数
·ANCOUNT表示answer section的RR个数
·NSCOUNT表示authority records section的RR个数
·ARCOUNT表示additional records section的RR个数
*/

// QR字段的值定义
#define HEADER_QR_QUERY 0
#define HEADER_QR_ANSWER 1

// OPCODE字段的值定义
#define HEADER_OPCODE_QUERY 0
#define HEADER_OPCODE_IQUERY 1
#define HEADER_OPCODE_STATUS 2

// RCODE字段的值定义
#define HEADER_RCODE_NO_ERROR 0
#define HEADER_RCODE_NAME_ERROR 3

// TYPE字段的值定义
#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
/*CNAME（Canonical Name）记录 是一种 DNS 记录类型，用于将一个域名别名（Alias）指向一个规范名称（Canonical Name）。
这意味着当 DNS 服务器接收到一个对别名的查询时，它会返回对应的规范名称，然后客户端会对该规范名称进行进一步解析。*/
#define TYPE_SOA 6
#define TYPE_PTR 12
#define TYPE_HINFO 13
#define TYPE_MINFO 14
#define TYPE_MX 15
#define TYPE_TXT 16
#define TYPE_AAAA 28

// CLASS字段的值定义
#define CLASS_IN 1
#define CLASS_NOT 254
#define CLASS_ALL 255

/* header
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

// DNS报文Header部分
typedef struct
{
    unsigned short id;
    unsigned char qr : 1;
    unsigned char opcode : 4;
    unsigned char aa : 1;
    unsigned char tc : 1;
    unsigned char rd : 1;
    unsigned char ra : 1;
    unsigned char z : 3;
    unsigned char rcode : 4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} Dns_Header;


/* Question
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

// DNS报文Question部分
typedef struct Question
{
    unsigned char* qname;
    unsigned short qtype;
    unsigned short qclass;
    struct Question* next;
} Dns_Question;

/*RR
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

// Resource Record
typedef struct RR
{
    unsigned char* name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short rdlength;
    unsigned char* rdata;
    struct RR* next;
} Dns_RR;

// DNS报文
typedef struct
{
    Dns_Header* header;
    Dns_Question* question;
    Dns_RR* RRs;
} Dns_Msg;

#endif // DNS_MSG_H