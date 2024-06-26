#ifndef CACHE_H
#define CACHE_H

#include <time.h>
#include "murmurhash.h"

#define CACHE_SIZE 997

// ������ṹ��
struct CacheEntry
{
    unsigned char domain[512]; // ����
    unsigned char ipAddr[16];  // IPv4 ��ַ
    unsigned char ipAddr6[40]; // IPv6 ��ַ
    time_t expireTime;         // ����ʱ��
    struct CacheEntry* prev;   // ǰ��ָ��
    struct CacheEntry* next;   // ���ָ��
};

// ����ṹ��
struct Cache
{
    struct CacheEntry* table[CACHE_SIZE]; // ��ϣ��
    struct CacheEntry* head;              // ����ͷָ��
    struct CacheEntry* tail;              // ����βָ��
};

// ��ʼ������
void initCache(struct Cache* cache);

// �����ϣֵ
unsigned int hashCode(const unsigned char* domain);

// ���һ�����
int findEntry(struct Cache* cache, const unsigned char* domain, unsigned char* ipAddr, int ipVersion);

// ��ӻ�����
void addEntry(struct Cache* cache, const unsigned char* domain, const unsigned char* ipAddr, int ipVersion, time_t ttl);

// ɾ��������
void removeExpiredEntries(struct Cache* cache);

// ��ջ���
void clearCache(struct Cache* cache);

// ��ӡ��������
void printCache(struct Cache* cache);

#endif /* CACHE_H */