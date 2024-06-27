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

// ���ֽ�������ȡ��header������
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

// �����ֽ����е�DNS����ͷ��������䵽Dns_Header�ṹ����
void getHeader(Dns_Header* header, const unsigned char* bytestream)
{
    // ���ֽ�������ȡ��ת��DNS����ͷ���ֶ�
    header->id = ntohs(*(unsigned short*)bytestream); // ����ID��ʹ��ntohs�������ֽ�˳��ת��Ϊ�����ֽ�˳��
    header->qr = (bytestream[2] >> 7) & 1; // ��ѯ/��Ӧ��־λ
    header->opcode = (bytestream[2] >> 3) & 0x0f; // ������
    header->aa = (bytestream[2] >> 2) & 1; // ��Ȩ�ش��־
    header->tc = (bytestream[2] >> 1) & 1; // �ضϱ�־
    header->rd = (bytestream[2]) & 1; // �ݹ��ѯ��־
    header->ra = (bytestream[3] >> 7) & 1; // �����Ա�־
    header->z = (bytestream[3] >> 4) & 0x07; // �����ֶΣ�����Ϊ0
    header->rcode = (bytestream[3]) & 0x0f; // ��Ӧ��
    header->qdcount = ntohs(*(unsigned short*)(bytestream + 4)); // ���������¼��
    header->ancount = ntohs(*(unsigned short*)(bytestream + 6)); // �ش������¼��
    header->nscount = ntohs(*(unsigned short*)(bytestream + 8)); // ��Ȩ�����¼��
    header->arcount = ntohs(*(unsigned short*)(bytestream + 10)); // ���������¼��
}

// ���ֽ�������ȡ���������洢��ָ����qname�����У�ͬʱ����offset��ʾ��ƫ����
void getName(unsigned char* qname, const unsigned char* bytestream, unsigned short* offset)
{
    while (*(bytestream + *offset) != 0) // ÿ����ǩ��0������������0ʱ��ʾ��������
    {
        if (((*(bytestream + *offset) >> 6) & 3) == 3) // �ж��Ƿ�Ϊѹ����ǩ
        {
            unsigned short new_offset = ntohs(*(unsigned short*)(bytestream + *offset)) & 0x3fff; // ��ȡ�µ�ƫ����
            getName(qname, bytestream, &new_offset); // �ݹ鴦��ѹ��������
            (*offset) += 2; // ����ƫ����������ѹ����ǩ��2���ֽ�
            return;
        }
        *qname = *(bytestream + *offset); // ����ǰ�ֽ���Ϊ������һ���ִ���qname����
        qname++; // ָ����һ��λ��
        (*offset)++; // ����ƫ������ָ����һ���ֽ�
    }
    (*offset)++; // ����ĩβ��0�ֽ�
    *qname = '\0'; // ����ַ���������־
}


// ���ֽ�������ȡ��question������
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

// ���ֽ�������ȡDNS��ѯ���ֵ�������Ϣ������䵽Dns_Question�ṹ����
void getQuestion(Dns_Question* question, const unsigned char* bytestream, unsigned short* offset)
{
    // ��̬�����ڴ�洢���������
    question->qname = (unsigned char*)malloc(sizeof(unsigned char) * UDP_MAX);
    if (!question->qname)
    {
        puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
        exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
    }

    // ��ȡ������Ϣ�����洢��question->qname�У�ͬʱ����offset
    getName(question->qname, bytestream, offset);

    // ��ȡ�������ͣ�qtype���������ࣨqclass������ת��Ϊ�����ֽ�˳��
    question->qtype = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // ����offset���������������ֶ�

    question->qclass = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // ����offset�������������ֶ�
}


// ���ֽ�������ȡRR������
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

// ���ֽ�������ȡDNS��Դ��¼��Resource Record����Ϣ������䵽Dns_RR�ṹ����
void getRR(Dns_RR* RR, const unsigned char* bytestream, unsigned short* offset)
{
    // ��̬�����ڴ�洢��Դ��¼������
    RR->name = (unsigned char*)malloc(sizeof(unsigned char) * UDP_MAX);
    if (!RR->name)
    {
        puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
        exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
    }

    // ��ȡ������Ϣ�����洢��RR->name�У�ͬʱ����offset
    getName(RR->name, bytestream, offset);

    // ��ȡ��Դ��¼�����ͣ�type�����ࣨclass����TTL�����ݳ��ȣ�rdlength������ת��Ϊ�����ֽ�˳��
    RR->type = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // ����offset�����������ֶ�

    RR->_class = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // ����offset���������ֶ�

    RR->ttl = ntohl(*(unsigned int*)(bytestream + *offset));
    (*offset) += 4; // ����offset������TTL�ֶ�

    RR->rdlength = ntohs(*(unsigned short*)(bytestream + *offset));
    (*offset) += 2; // ����offset���������ݳ����ֶ�

    // ��̬�����ڴ�洢��Դ��¼�����ݣ�rdata��������rdlength������Ӧ���ȵ��ֽ�����������ַ�����β
    RR->rdata = (unsigned char*)malloc(sizeof(unsigned char) * RR->rdlength + 1);
    if (!RR->rdata)
    {
        puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
        exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
    }
    memcpy(RR->rdata, bytestream + *offset, RR->rdlength);
    RR->rdata[RR->rdlength] = '\0'; // ����ַ�����β
    (*offset) += RR->rdlength; // ����offset�����������ֶ�
}

// ��ԭʼ��IPv4��ַת��Ϊ���ʮ������ʽ���ַ�����ʾ
void transIPv4(unsigned char* original, unsigned char* IPv4)
{
    // ʹ��sprintf��ԭʼ��IPv4��ַת��Ϊ�ַ�����ʽ
    sprintf((char*)(IPv4), "%d.%d.%d.%d", original[0], original[1], original[2], original[3]);
}

// ��ԭʼ��IPv6��ַת��Ϊð��ʮ��������ʽ���ַ�����ʾ
void transIPv6(unsigned char* original, unsigned char* IPv6)
{
    // ʹ��sprintf��ԭʼ��IPv6��ַת��Ϊð��ʮ��������ʽ���ַ�����ʽ
    sprintf((char*)(IPv6), "%x:%x:%x:%x:%x:%x:%x:%x", ntohs(*(unsigned short*)(original)),
        ntohs(*(unsigned short*)(original + 2)), ntohs(*(unsigned short*)(original + 4)),
        ntohs(*(unsigned short*)(original + 6)), ntohs(*(unsigned short*)(original + 8)),
        ntohs(*(unsigned short*)(original + 10)), ntohs(*(unsigned short*)(original + 12)),
        ntohs(*(unsigned short*)(original + 14)));
}

// ��ԭʼ��DNS������ʽת��Ϊ�����ʽ���ַ�����ʾ
void transDN(unsigned char* original, unsigned char* DN)
{
    while (*original != 0)
    {
        unsigned short len = *original; // �����εĳ���
        original++;
        memcpy(DN, original, len); // ���������ε�Ŀ���ַ�����
        original += len; // �ƶ�ԭʼ����ָ��
        DN += len; // �ƶ�Ŀ���ַ���ָ��
        *DN = '.'; // ��ӵ�ָ���
        DN++;
    }
    *(DN - 1) = '\0'; // �����һ�����Ϊ�ַ���������
}

// �ͷ�DNS��Ϣ�ṹ�弰���ڴ�
void releaseMsg(Dns_Msg* msg)
{
    if (!msg)
        return;

    // �ͷ�header�����ڴ�
    free(msg->header);

    // �ͷ�question�����ڴ�
    Dns_Question* pQue = msg->question;
    while (pQue)
    {
        if (pQue->qname)
            free(pQue->qname);
        Dns_Question* temp = pQue;
        pQue = pQue->next;
        free(temp);
    }

    // �ͷ�RRs����Դ��¼�������ڴ�
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

    // �ͷ�DNS��Ϣ�ṹ�屾����ڴ�
    free(msg);
}


// ���ֽ���ת��ΪDNS��Ϣ�ṹ��
Dns_Msg* bytestream_to_dnsmsg(const unsigned char* bytestream, unsigned short* offset)
{
    Dns_Msg* msg = (Dns_Msg*)malloc(sizeof(Dns_Msg));
    if (!msg)
    {
        puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
        exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
    }

    // ת��header���֣���̬�����ڴ�洢header������getHeader�������header��Ϣ
    msg->header = (Dns_Header*)malloc(sizeof(Dns_Header));
    if (!msg->header)
    {
        puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
        exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
    }
    getHeader(msg->header, bytestream); // ���header��Ϣ

    *offset = 12; // ���ó�ʼƫ����Ϊ12������header����

    // ת��question���֣�����ÿ��question��ת��ΪDns_Question�ṹ��
    msg->question = NULL;
    Dns_Question* question_tail = NULL;
    for (int i = 0; i < msg->header->qdcount; i++)
    {
        Dns_Question* current = (Dns_Question*)malloc(sizeof(Dns_Question));
        if (!current)
        {
            puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
            exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
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
        getQuestion(current, bytestream, offset); // ��䵱ǰquestion��Ϣ
    }

    // ת��answer��authority��additional���֣�����ÿ����Դ��¼��ת��ΪDns_RR�ṹ��
    unsigned short total_length = msg->header->ancount + msg->header->nscount + msg->header->arcount;
    msg->RRs = NULL;
    Dns_RR* RRs_tail = NULL;
    for (int i = 0; i < total_length; i++)
    {
        Dns_RR* current = (Dns_RR*)malloc(sizeof(Dns_RR));
        if (!current)
        {
            puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
            exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
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
        getRR(current, bytestream, offset); // ��䵱ǰ��Դ��¼��Ϣ
    }

    return msg; // �������������DNS��Ϣ�ṹ��
}


// ��DNS��Ϣ�ṹ���е�header���������ֽ���
void putHeader(const Dns_Header* header, unsigned char* bytestream)
{
    // ����16λ��id�ֶΣ���8λ��ǰ����8λ�ں�
    bytestream[0] = header->id >> 8;
    bytestream[1] = header->id;

    // ����8λ�ı�־λ�ֶ�
    bytestream[2] = 0;
    bytestream[2] |= header->qr << 7;      // QR��־λ��1λ
    bytestream[2] |= header->opcode << 3;  // �����룬4λ
    bytestream[2] |= header->aa << 2;      // ��Ȩ�𰸱�־λ��1λ
    bytestream[2] |= header->tc << 1;      // �ضϱ�־λ��1λ
    bytestream[2] |= header->rd;           // �����ݹ��־λ��1λ

    // ����8λ����Ӧ���ֶ�
    bytestream[3] = 0;
    bytestream[3] |= header->ra << 7;      // �����Ա�־λ��1λ
    bytestream[3] |= header->z << 4;       // �����ֶΣ�3λ
    bytestream[3] |= header->rcode;        // ��Ӧ�룬4λ

    // ����16λ���������ֶ�
    bytestream[4] = header->qdcount >> 8;
    bytestream[5] = header->qdcount;

    // ����16λ�Ļش����ֶ�
    bytestream[6] = header->ancount >> 8;
    bytestream[7] = header->ancount;

    // ����16λ����Ȩ��¼���ֶ�
    bytestream[8] = header->nscount >> 8;
    bytestream[9] = header->nscount;

    // ����16λ�ĸ��Ӽ�¼���ֶ�
    bytestream[10] = header->arcount >> 8;
    bytestream[11] = header->arcount;
}

// ��DNS��Ϣ�ṹ���е�question���������ֽ���
void putQuestion(const Dns_Question* question, unsigned char* bytestream, unsigned short* offset)
{
    // ���������ֶε��ֽ����У�ֱ����������������0
    memcpy(bytestream + *offset, question->qname, strlen((char*)(question->qname)) + 1);
    *offset += strlen((char*)(question->qname)) + 1;

    // ����16λ�����������ֶ�
    *(bytestream + *offset) = question->qtype >> 8;
    (*offset)++;

    *(bytestream + *offset) = question->qtype;
    (*offset)++;

    // ����16λ���������ֶ�
    *(bytestream + *offset) = question->qclass >> 8;
    (*offset)++;

    *(bytestream + *offset) = question->qclass;
    (*offset)++;
}

// ��DNS��Ϣ�ṹ���е�RR����Դ��¼�����������ֽ���
void putRR(const Dns_RR* rr, unsigned char* bytestream, unsigned short* offset)
{
    // ���������ֶε��ֽ����У�ֱ����������������0
    memcpy(bytestream + *offset, rr->name, strlen((char*)(rr->name)) + 1);
    *offset += strlen((char*)(rr->name)) + 1;

    // ����16λ�������ֶ�
    *(bytestream + *offset) = rr->type >> 8;
    (*offset)++;

    *(bytestream + *offset) = rr->type;
    (*offset)++;

    // ����16λ�����ֶ�
    *(bytestream + *offset) = rr->_class >> 8;
    (*offset)++;

    *(bytestream + *offset) = rr->_class;
    (*offset)++;

    // ����32λ��TTL�ֶ�
    *(bytestream + *offset) = rr->ttl >> 24;
    (*offset)++;

    *(bytestream + *offset) = rr->ttl >> 16;
    (*offset)++;

    *(bytestream + *offset) = rr->ttl >> 8;
    (*offset)++;

    *(bytestream + *offset) = rr->ttl;
    (*offset)++;

    // ����16λ�����ݳ����ֶ�
    *(bytestream + *offset) = rr->rdlength >> 8;
    (*offset)++;

    *(bytestream + *offset) = rr->rdlength;
    (*offset)++;

    // ����rdata�ֶε��ֽ�����
    memcpy(bytestream + *offset, rr->rdata, rr->rdlength);
    *offset += rr->rdlength;
}

// ��DNS��Ϣ�ṹ��ת��Ϊ�ֽ�����ʾ
unsigned char* dnsmsg_to_bytestream(const Dns_Msg* msg)
{
    unsigned char* bytestream = (unsigned char*)malloc(sizeof(unsigned char) * UDP_MAX);
    if (!bytestream)
    {
        puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
        exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
    }

    // ����header���ֵ��ֽ�����
    putHeader(msg->header, bytestream);

    // ���ó�ʼƫ����Ϊ12����������header����
    unsigned short offset = 12;

    // ����question���ֵ��ֽ�����
    Dns_Question* question = msg->question;
    while (question)
    {
        putQuestion(question, bytestream, &offset);
        question = question->next;
    }

    // ����answer��authority��additional���ֵ��ֽ�����
    Dns_RR* rr = msg->RRs;
    while (rr)
    {
        putRR(rr, bytestream, &offset);
        rr = rr->next;
    }

    return bytestream;
}
