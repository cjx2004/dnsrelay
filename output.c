#include "output.h"
#include <stdio.h>
#include "msg_convert.h"
#include <time.h>

#include "output.h"
#include <stdio.h>
#include "msg_convert.h"
#include <time.h>

/*
* RRInfo(Dns_RR* rr): ���������Դ��¼��Resource Record��RR������ϸ��Ϣ�����ݼ�¼���ͣ�IPv4��IPv6�������ͬ��ʽ�������ֶΡ�
*
* debug(Dns_Msg* msg): ���������Ϣ����ӡ���� DNS ���ĵĸ���������Ϣ����������ͷ�������ⲿ�֡�Ӧ�𲿷֡���Ȩ���ֺ͸��Ӳ��֡�������ǰ��� printTime() �� RRInfo() ������
*
* bytestreamInfo(unsigned char* bytestream): ����ֽ�����16���Ʊ�ʾ�����ֽ���ת��Ϊ DNS ��Ϣ�ṹ��󣬰�16���Ƹ�ʽ����ֽ������ݣ����ͷ�����ڴ档
*/



// ���������Ϣ����ӡDNS���ĵĸ�������
void debug(Dns_Msg* msg)
{


    // ��ӡ����ͷ����Ϣ
    printf("------------------------ͷ��------------------------\n");
    printf("ID:%2d  ", msg->header->id);
    printf("��Ӧ��־:%2d  ", msg->header->qr);
    printf("������:%2d  ", msg->header->opcode);
    printf("��Ȩ�ش�:%2d  ", msg->header->aa);
    printf("�ɽض�:%2d  ", msg->header->tc);
    printf("�ݹ�����:%2d  ", msg->header->rd);
    printf("�ݹ����:%2d\n", msg->header->ra);
    printf("��Ӧ��:%2d  ", msg->header->rcode);
    printf("������:%2d  ", msg->header->qdcount);
    printf("�ش���:%2d  ", msg->header->ancount);
    printf("��Ȩ��:%2d  ", msg->header->nscount);
    printf("������:%2d\n", msg->header->arcount);

    // ��ӡ���ⲿ����Ϣ
    Dns_Question* current_que = msg->question;
    printf("-----------------------����-----------------------\n");
    for (int i = 0; i < msg->header->qdcount; i++)
    {
        printf("���� %d\n", i + 1);
        unsigned char name[512];
        transDN(current_que->qname, name); // ת��������ʽ
        printf("����:%20s  ", name);
        printf("����:%2d  ", current_que->qtype);
        printf("���:%2d\n", current_que->qclass);
        current_que = current_que->next;
    }

    // ��ӡ�ش𲿷���Ϣ
    Dns_RR* rr = msg->RRs;
    if (msg->header->ancount)
    {
        printf("------------------------�ش�------------------------\n");
    }
    for (int i = 0; i < msg->header->ancount; i++)
    {
        printf("��Դ��¼ %d\n", i + 1);
        RRInfo(rr); // ���������Դ��¼����Ϣ
        rr = rr->next;
    }

    // ��ӡ��Ȩ������Ϣ
    if (msg->header->nscount)
    {
        printf("-----------------------��Ȩ----------------------\n");
    }
    for (int i = 0; i < msg->header->nscount; i++)
    {
        printf("��Դ��¼ %d\n", i + 1);
        RRInfo(rr); // ���������Դ��¼����Ϣ
        rr = rr->next;
    }

    // ��ӡ������Ϣ������Ϣ
    if (msg->header->arcount)
    {
        printf("----------------------����----------------------\n");
    }
    for (int i = 0; i < msg->header->arcount; i++)
    {
        printf("��Դ��¼ %d\n", i + 1);
        RRInfo(rr); // ���������Դ��¼����Ϣ
        rr = rr->next;
    }

    printf("------------------------------------------------------\n");
}

// ����ֽ�����16���Ʊ�ʾ
void bytestreamInfo(unsigned char* bytestream)
{
    unsigned short offset;
    Dns_Msg* msg = bytestream_to_dnsmsg(bytestream, &offset); // ���ֽ���ת��ΪDNS��Ϣ�ṹ��
    for (int i = 0; i < (int)(offset); i += 16)
    {
        printf("%04lx: ", i); // ���ƫ�Ƶ�ַ
        for (int j = i; j < i + 16 && j < (int)(offset); j++)
        {
            printf("%02x ", (unsigned char)bytestream[j]); // ���16���Ʊ�ʾ���ֽ�
        }
        printf("\n");
    }
    releaseMsg(msg); // �ͷ�DNS��Ϣ�ṹ���ڴ�
}

// �������Resource Record����Ϣ
void RRInfo(Dns_RR* rr)
{
    unsigned char name[UDP_MAX];
    transDN(rr->name, name); // ת��������ʽ
    printf("����:%20s  ", name);
    printf("����:%2d  ", rr->type);
    printf("���:%2d\n", rr->_class);
    printf("����ʱ��:%2d  ", rr->ttl);
    printf("���ݳ���:%2d  ", rr->rdlength);

    // ���ݼ�¼���������ͬ��ʽ�������ֶ�
    if (rr->type == TYPE_A)
    {
        unsigned char IPv4[20];
        transIPv4(rr->rdata, IPv4); // ת��IPv4��ַ��ʽ
        printf("��������:%20s", IPv4);
    }
    else if (rr->type == TYPE_AAAA)
    {
        unsigned char IPv6[40];
        transIPv6(rr->rdata, IPv6); // ת��IPv6��ַ��ʽ
        printf("��������:%20s", IPv6);
    }
    printf("\n");
}