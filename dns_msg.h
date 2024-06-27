#ifndef DNS_MSG_H
#define DNS_MSG_H

#define UDP_MAX 512

/*
��QR��1 bit����ѯ/��Ӧ��־��0Ϊ��ѯ��1Ϊ��Ӧ��
��opcode��1 bit��0��ʾ��׼��ѯ��1��ʾ�����ѯ��2��ʾ������ת̬����
��AA��1 bit����ʾ��Ȩ�ش�
��TC��1 bit����ʾ�ɽضϵ�
��RD��1 bit����ʾ�����ݹ�
��RA��1 bit����ʾ���õݹ�
��RCODE��4 bit����ʾ�����룬0��ʾû�в��3��ʾ���ֲ��2��ʾ����������Server Failure��
��3�������ֶΣ��ܹ�8�ֽڣ������Ա�ʾ������ĸ��������Ŀ��
��QDCOUNT��ʾquestion section���������
��ANCOUNT��ʾanswer section��RR����
��NSCOUNT��ʾauthority records section��RR����
��ARCOUNT��ʾadditional records section��RR����
*/

// QR�ֶε�ֵ����
#define HEADER_QR_QUERY 0
#define HEADER_QR_ANSWER 1

// OPCODE�ֶε�ֵ����
#define HEADER_OPCODE_QUERY 0
#define HEADER_OPCODE_IQUERY 1
#define HEADER_OPCODE_STATUS 2

// RCODE�ֶε�ֵ����
#define HEADER_RCODE_NO_ERROR 0
#define HEADER_RCODE_NAME_ERROR 3

// TYPE�ֶε�ֵ����
#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
/*CNAME��Canonical Name����¼ ��һ�� DNS ��¼���ͣ����ڽ�һ������������Alias��ָ��һ���淶���ƣ�Canonical Name����
����ζ�ŵ� DNS ���������յ�һ���Ա����Ĳ�ѯʱ�����᷵�ض�Ӧ�Ĺ淶���ƣ�Ȼ��ͻ��˻�Ըù淶���ƽ��н�һ��������*/
#define TYPE_SOA 6
#define TYPE_PTR 12
#define TYPE_HINFO 13
#define TYPE_MINFO 14
#define TYPE_MX 15
#define TYPE_TXT 16
#define TYPE_AAAA 28

// CLASS�ֶε�ֵ����
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

// DNS����Header����
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

// DNS����Question����
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

// DNS����
typedef struct
{
    Dns_Header* header;
    Dns_Question* question;
    Dns_RR* RRs;
} Dns_Msg;

#endif // DNS_MSG_H