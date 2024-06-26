#include "id_converter.h"
#include <stdlib.h>
#include <string.h>

#define MAX_CLIENTS 65536  // ���ͻ�������
unsigned short index = 0;  // ��ǰӳ���λ��
KeyValue map[MAX_CLIENTS]; // ���ڴ洢id��clientAddr��ӳ��
int used[MAX_CLIENTS];

// ���ڴ洢id��clientAddr��ӳ��
int trans_port_id(unsigned short id, struct sockaddr_in clientAddr)
{
    int temp = index;
    while (used[index] == 1) // �ҵ�һ��δʹ�õ�λ��
    {
        index = (index + 1) % MAX_CLIENTS;
        if (index == temp) // �Ѿ�����������λ��
            return temp + 1;
    }

    map[index].value = index; // ����ӳ��
    map[index].key.id = id;
    map[index].key.clientAddr = clientAddr;
    used[index] = 1; // ���Ϊ��ʹ��
    return index;    // ����ӳ���ֵ
}

// ����ԭʼid
unsigned short find_id(unsigned Value)
{
    return map[Value].key.id;
}

// ����ԭʼclientAddr
struct sockaddr_in find_clientAddr(unsigned Value)
{
    return map[Value].key.clientAddr;
}

// �Ƴ�ӳ��
void remove_id(unsigned Value)
{
    used[Value] = 0;
}