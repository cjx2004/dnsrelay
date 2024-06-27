#ifndef OUTPUT_H
#define OUTPUT_H

#include "dns_msg.h"

/*
*RRInfo(Dns_RR rr)**: ���������Դ��¼��Resource Record��RR������ϸ��Ϣ�����ݼ�¼���ͣ�IPv4��IPv6�������ͬ��ʽ�������ֶΡ�

*debug(Dns_Msg msg)**: ���������Ϣ����ӡ���� DNS ���ĵĸ���������Ϣ����������ͷ�������ⲿ�֡�Ӧ�𲿷֡���Ȩ���ֺ͸��Ӳ��֡�������ǰ��� printTime() �� RRInfo() ������

*bytestreamInfo(unsigned char bytestream)**: ����ֽ�����16���Ʊ�ʾ�����ֽ���ת��Ϊ DNS ��Ϣ�ṹ��󣬰�16���Ƹ�ʽ����ֽ������ݣ����ͷ�����ڴ档
*/

// ���������Ϣ
void debug(Dns_Msg* msg);

// ���resource record
void RRInfo(Dns_RR* rr);

// ���16�����ֽ���
void bytestreamInfo(unsigned char* bytestream);


#endif // OUTPUT_H#pragma once
