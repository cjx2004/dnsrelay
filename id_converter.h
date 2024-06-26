#ifndef ID_CONVERTER_H
#define ID_CONVERTER_H

#include <winsock2.h>

typedef struct
{
    unsigned short id;
    struct sockaddr_in clientAddr;
} Key; // ���ڴ洢id��clientAddr��ӳ��ļ�

typedef struct
{
    Key key;
    unsigned short value;
} KeyValue; // ���ڴ洢id��clientAddr��ӳ��ļ�ֵ��

// ���ڴ洢id��clientAddr��ӳ��
int trans_port_id(unsigned short id, struct sockaddr_in clientAddr);

// ����ԭʼid
unsigned short find_id(unsigned Value);

// ����ԭʼclientAddr
struct sockaddr_in find_clientAddr(unsigned Value);

// �Ƴ�ӳ��
void remove_id(unsigned Value);

#endif /* ID_CONVERTER_H */