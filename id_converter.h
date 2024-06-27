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

// 用于存储id和clientAddr的映射的键
typedef struct {
    unsigned short id;
    struct sockaddr_in clientAddr;
} Key;

// 用于存储id和clientAddr的映射的键值对
typedef struct {
    Key key;
    unsigned short value;
} KeyValue;

// 用于存储id和clientAddr的映射
int translate_id(unsigned short id, struct sockaddr_in clientAddr);

// 查找原始id
unsigned short retrieve_id(unsigned index);

// 查找原始clientAddr
struct sockaddr_in retrieve_clientAddr(unsigned index);

// 移除映射
void remove_mapping(unsigned index);

#endif /* ID_CONVERTER_H */
