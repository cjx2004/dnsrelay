#ifndef ID_CONVERTER_H
#define ID_CONVERTER_H

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

// ���ڴ洢id��clientAddr��ӳ��ļ�
typedef struct {
    unsigned short id;
    struct sockaddr_in clientAddr;
} Key;

// ���ڴ洢id��clientAddr��ӳ��ļ�ֵ��
typedef struct {
    Key key;
    unsigned short value;
} KeyValue;

// ���ڴ洢id��clientAddr��ӳ��
int translate_id(unsigned short id, struct sockaddr_in clientAddr);

// ����ԭʼid
unsigned short retrieve_id(unsigned index);

// ����ԭʼclientAddr
struct sockaddr_in retrieve_clientAddr(unsigned index);

// �Ƴ�ӳ��
void remove_mapping(unsigned index);

#endif /* ID_CONVERTER_H */
