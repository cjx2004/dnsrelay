//���������������ʵ����DNS�м̷������д���͹���DNS��Ϣ�ĺ��Ĺ��ܡ�

#include "msg_conduct.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "msg_convert.h"

/*
����: ��һ��Resource Record����Դ��¼����ӵ�DNS��Ϣ��answer�ֶ��С����������Ҫ���ڹ���DNS��Ӧ�����е�answer���֣���Ӧ�ͻ��˵�DNS��ѯ��
*/

// ���һ��Resource Record��DNS��Ϣ��answer�ֶ���
void addAnswer(Dns_Msg* msg, const unsigned char* IP, unsigned int _ttl, unsigned short _type)
{
    // ������վ���أ������IPv4��IPv6���͵���Ӧ����IP��ַΪ0.0.0.0��ȫ0��������Ӧ��Ϊ3
    if ((_type == TYPE_A || _type == TYPE_AAAA) && *(unsigned int*)(IP) == 0)
    {
        msg->header->rcode = 3;
    }
    // ����header�ֶε�ֵ����Ӧ��־qrΪ1����Ӧ��Ϣ�����ݹ��ѯrdΪ1�������Ա�־raΪ1���ش����ancount��һ
    
    msg->header->ra = 1;
    msg->header->ancount++;
    msg->header->qr = 1;
    msg->header->rd = 1;

    // ���һ��Resource Record��answer�ֶ���
    Dns_RR* rr = msg->RRs;
    Dns_RR* prev = NULL;
    while (rr)
    {
        prev = rr;
        rr = rr->next;
    }

    if (prev)
    {
        // ����Ѿ�����ǰһ��RR����̬����һ���µ�RR�����ӵ�����β��
        rr = (Dns_RR*)malloc(sizeof(Dns_RR));
        if (!rr)
        {
            puts("��̬�����ڴ�ʧ��"); // �ڴ����ʧ����ʾ
            exit(1); // �˳����򣬴����ڴ����ʧ�ܵ����
        }
        prev->next = rr; // ǰһ��RR��nextָ���µ�RR
        rr->next = NULL; // �µ�RR��next��ΪNULL����ʾ�����β
    }
    else
    {
        // ���prevΪ�գ�˵����ǰ�����л�û��RR��ֱ��Ϊmsg��RRs�ֶη����ڴ棬���趨nextΪNULL
        msg->RRs = (Dns_RR*)malloc(sizeof(Dns_RR));
        msg->RRs->next = NULL;
        rr = msg->RRs;
    }

    // �������ⲿ�ֵ�������answer���ֵ�RR��name�ֶ�
    rr->name = (unsigned char*)malloc(sizeof(unsigned char) * UDP_MAX);
    memcpy(rr->name, msg->question->qname, strlen((char*)(msg->question->qname)) + 1);

    // ����RR�����͡��ࡢTTL�����ݳ��Ⱥ�����
    rr->type = _type;
    rr->_class = CLASS_IN;
    rr->ttl = _ttl;

    // ������Ӧ�����ͣ�IPv4��IPv6�����������ݳ��Ⱥ�����
    if (_type == TYPE_A)
    {
        rr->rdlength = 4; // IPv4��ַ����Ϊ4�ֽ�
    }
    else
    {
        rr->rdlength = 16; // IPv6��ַ����Ϊ16�ֽ�
    }
    rr->rdata = (unsigned char*)malloc(sizeof(unsigned char) * rr->rdlength);
    memcpy(rr->rdata, IP, rr->rdlength); // ����IP��ַ���ݵ�RR��rdata�ֶ�
}


/*����: ���ⲿDNS�Ļظ���������ȡ������DN����IP��ַ���Լ���ص�TTL��������Ϣ��
����:
���ֽ�����ʽ��DNS�ظ�����ת��ΪDNS��Ϣ�ṹ�塣
��ȡDNS��Ϣ�е����ⲿ�ֵ���������ͨ������transDN����ת����
����DNS��Ϣ�е�RRs������������ΪIPv4��TYPE_A����IPv6��TYPE_AAAA����Resource Record����ȡ��һ��ƥ�䵽��IP��ַ����Ӧ��TTL�����͡�
�ͷ�ʹ�õ��ڴ���Դ�������ͷ�DNS��Ϣ�ṹ�塣
��ע: ����������ڽ�������ȡ�ⲿDNS���������ص�DNS��Ӧ�����е���Ҫ��Ϣ���Ա���������ת�����ͻ��ˡ�
*/

// ���ⲿDNS�Ļظ���������ȡ������IP��ַ
void getDN_IP(const unsigned char* bytestream, unsigned char* DN, unsigned char* IP, unsigned int* _ttl, unsigned short* _type)
{
    unsigned short offset;
    Dns_Msg* msg = btod(bytestream, &offset);
    transDN(msg->question->qname, DN);
    Dns_RR* rr = msg->RRs;
    //ȡRR������Ϊipv4����v6�ĵ�һ��ip��ַ
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