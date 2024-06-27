#include "id_converter.h"
#include <stdlib.h>
#include <string.h>

#define MAX_CLIENTS 65536  // ���ͻ�������

unsigned short currentIndex = 0;  // ��ǰӳ���λ��

KeyValue idMapping[MAX_CLIENTS]; // ���ڴ洢id��clientAddr��ӳ��
int isUsed[MAX_CLIENTS]; // ���ڼ�¼λ���Ƿ�ʹ��

/**
 * ��ID�Ϳͻ��˵�ַת�����洢ӳ��
 * @param id �ͻ��˵�ID
 * @param clientAddr �ͻ��˵ĵ�ַ��Ϣ
 * @return ���ش洢ӳ���λ������
 */
int translate_id(unsigned short id, struct sockaddr_in clientAddr)
{
    int startIndex = currentIndex;
    // ����һ��δ��ʹ�õ�λ��
    while (isUsed[currentIndex] == 1)
    {
        currentIndex = (currentIndex + 1) % MAX_CLIENTS;
        // �������������λ�ö�û���ҵ�����λ�ã�������һ��λ��
        if (currentIndex == startIndex)
            return startIndex + 1;
    }

    // ����ӳ����Ϣ
    idMapping[currentIndex].value = currentIndex;
    idMapping[currentIndex].key.id = id;
    idMapping[currentIndex].key.clientAddr = clientAddr;
    isUsed[currentIndex] = 1; // ���Ϊ��ʹ��
    return currentIndex;    // ����ӳ�������ֵ
}

/**
 * ���ݴ洢��λ����������ԭʼ��ID
 * @param index �洢��λ������
 * @return ����ԭʼ��ID
 */
unsigned short retrieve_id(unsigned index)
{
    return idMapping[index].key.id;
}

/**
 * ���ݴ洢��λ����������ԭʼ�Ŀͻ��˵�ַ
 * @param index �洢��λ������
 * @return ����ԭʼ�Ŀͻ��˵�ַ
 */
struct sockaddr_in retrieve_clientAddr(unsigned index)
{
    return idMapping[index].key.clientAddr;
}

/**
 * �Ƴ�ָ��λ��������ӳ��
 * @param index Ҫ�Ƴ���ӳ���λ������
 */
void remove_mapping(unsigned index)
{
    isUsed[index] = 0;
}
