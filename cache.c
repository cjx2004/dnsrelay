#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cache.h"
#include <WS2tcpip.h>

/*��ϣ��Ĳ���Ч��ΪO(1)������ı�����O(N)��
LRU ��������е���Ҫ���������ʡ���ӡ���̭���������� O(1) ʱ�临�Ӷ�����ɣ�������ڹ�ϣ���˫������Ľ��ʹ��
*/

/*LRU˼·��
�����·��ʵ�cache�����Ƶ�����ͷ��cache����Ӻ�ʼɾ��cache����
*/

// ��ʼ������
void initCache(struct Cache* cache)
{
    memset(cache->table, 0, sizeof(cache->table)); // ����ϣ������
    cache->head = NULL; // ����ͷָ���ÿ�
    cache->tail = NULL; // ����βָ���ÿ�
}

// �����ϣֵ
unsigned int calculateHash(const unsigned char* domain)
{
    if (domain == NULL) {
        printf("Error: Domain is NULL!\n");
        return 0;
    }
    uint32_t hashValue = MurmurHash(domain, strlen((const char*)domain), 0) % CACHE_SIZE;
    return (unsigned int)hashValue;
}

// ��ӻ�����
void insertCacheEntry(struct Cache* cache, const unsigned char* domain, const unsigned char* ipAddr, int ipVersion, time_t ttl)
{
    if (domain == NULL) {
        printf("Error: Domain is NULL!\n");
        return;
    }
    printf("Inserting into cache...\n");
    size_t domainLen = strlen((const char*)domain);
    unsigned int hash = calculateHash(domain);
    time_t now = time(NULL);

    struct CacheEntry* entry = (struct CacheEntry*)malloc(sizeof(struct CacheEntry));
    if (entry == NULL) {
        printf("Memory allocation failed!\n");
        return;
    }

    memcpy(entry->domain, domain, domainLen + 1);
    entry->domain[domainLen] = '\0';

    if (ipVersion == 1) {
        memcpy(entry->ipAddr, ipAddr, sizeof(entry->ipAddr));
    }
    else if (ipVersion == 28) {
        memcpy(entry->ipAddr6, ipAddr, sizeof(entry->ipAddr6));
    }
    else {
        printf("Error: Invalid IP version!\n");
        free(entry);
        return;
    }

    entry->expireTime = now + ttl;

    // Check if cache is full, remove least recently used entry according to LRU strategy
    int isFull = 1;
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache->table[i] == NULL) {
            isFull = 0;
            break;
        }
        else {
            removeLeastRecentlyUsed(cache);
        }
    }

    entry->prev = NULL;
    entry->next = cache->head;
    if (cache->head != NULL)
        cache->head->prev = entry;
    cache->head = entry;
    if (cache->tail == NULL)
        cache->tail = entry;

    entry->prev = NULL;
    entry->next = cache->table[hash];
    if (cache->table[hash] != NULL)
        cache->table[hash]->prev = entry;
    cache->table[hash] = entry;
    printf("Successfully added to cache!\n");
    removeExpiredEntries(cache);
}

// ɾ�����ڵĻ�����
void purgeExpiredEntries(struct Cache* cache)
{
    time_t now = time(NULL);
    struct CacheEntry* entry = cache->tail;
    while (entry != NULL && entry->expireTime < now)
    {
        struct CacheEntry* prev = entry->prev;
        if (prev != NULL)
        {
            prev->next = NULL;
            cache->tail = prev;
        }
        else
        {
            cache->tail = NULL;
            cache->head = NULL;
        }
        free(entry);
        entry = cache->tail;
    }
}

// ��ջ���
void clearCacheEntries(struct Cache* cache)
{
    for (int i = 0; i < CACHE_SIZE; i++)
    {
        struct CacheEntry* entry = cache->table[i];
        while (entry != NULL)
        {
            struct CacheEntry* next = entry->next;
            free(entry);
            entry = next;
        }
        cache->table[i] = NULL;
    }
    cache->head = NULL;
    cache->tail = NULL;
}

// ���һ�����
int retrieveCacheEntry(struct Cache* cache, const unsigned char* domain, unsigned char* ipAddr, int ipVersion)
{
    size_t domainLen = strlen((const char*)domain);
    unsigned int hash = calculateHash(domain);
    time_t now = time(NULL);

    printf("Searching cache for domain: %s, hash: %u \n", domain, hash);

    struct CacheEntry* entry = cache->table[hash];

    while (entry != NULL)
    {
        printf("Accessing corresponding hash field\n");
        if (entry->expireTime < 0)
        {
            cache->table[hash] = NULL;
            return 0;
        }
        if (cache->head != cache->tail)
        {
            purgeExpiredEntries(cache);
            printf("Successful search in cache, domain: %s\n", domain);
            return 0;
        }

        if (strcmp((const char*)entry->domain, (const char*)domain) == 0 && ((ipVersion == 1 && entry->ipAddr != NULL) || (ipVersion == 28 && entry->ipAddr6 != NULL)))
        {
            printf("Domain found!\n");

            if (entry->expireTime >= now)
            {
                if (entry->prev != NULL)
                    entry->prev->next = entry->next;
                else
                    cache->head = entry->next;
                if (entry->next != NULL)
                    entry->next->prev = entry->prev;
                else
                    cache->tail = entry->prev;

                entry->expireTime = now + 60;
                entry->prev = NULL;
                entry->next = cache->head;
                cache->head = entry;

                if (ipVersion == 1)
                    memcpy(ipAddr, entry->ipAddr, sizeof(entry->ipAddr));
                else
                    memcpy(ipAddr, entry->ipAddr6, sizeof(entry->ipAddr6));

                return 1;
            }
            else
            {
                if (entry->prev != NULL)
                    entry->prev->next = entry->next;
                else
                    cache->table[hash] = entry->next;
                if (entry->next != NULL)
                    entry->next->prev = entry->prev;
                else
                    cache->tail = entry->prev;
                free(entry);
                return 0;
            }
        }
        entry = entry->next;
    }

    return 0;
}


// ��ӡ��������
void printCache(struct Cache* cache)
{
    printf("--------------------------Cache Contents-----------------------------\n");
    for (int i = 0; i < CACHE_SIZE; i++)
    {
        struct CacheEntry* entry = cache->table[i];
        while (entry != NULL)
        {
            char ipStr[INET6_ADDRSTRLEN] = { 0 };
            /*if (entry->ipAddr[0] != 0)
            {
                // ��ӡIPv4��ַ
                snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", entry->ipAddr[0], entry->ipAddr[1], entry->ipAddr[2], entry->ipAddr[3]);
            }
            else if (entry->ipAddr6[0] != 0)
            {
                // ��ӡIPv6��ַ
                
                sprintf(ipStr, "%x:%x:%x:%x:%x:%x:%x:%x",
                    entry->ipAddr6[0] << 8 | entry->ipAddr6[1], entry->ipAddr6[2] << 8 | entry->ipAddr6[3],
                    entry->ipAddr6[4] << 8 | entry->ipAddr6[5], entry->ipAddr6[6] << 8 | entry->ipAddr6[7],
                    entry->ipAddr6[8] << 8 | entry->ipAddr6[9], entry->ipAddr6[10] << 8 | entry->ipAddr6[11],
                    entry->ipAddr6[12] << 8 | entry->ipAddr6[13], entry->ipAddr6[14] << 8 | entry->ipAddr6[15]);
            }*/
            snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", entry->ipAddr[0], entry->ipAddr[1], entry->ipAddr[2], entry->ipAddr[3]);
            printf("[%d] Domain: %s, IP: %s  ExpireTime: %ld\n", i, entry->domain, ipStr, entry->expireTime);
            entry = entry->next;
        }
    }
}

// ɾ�����δʹ�õĻ�����
void removeLeastRecentlyUsed(struct Cache* cache)
{
    while (cache->tail != NULL)
    {
        // ������β��ɾ�����δʹ�õĻ�����
        struct CacheEntry* entry = cache->tail;
        unsigned int hash = calculateHash(entry->domain); // ���������Ĺ�ϣֵ

        // �ӹ�ϣ����ɾ����ǰ�ڵ�
        if (entry->prev != NULL)
        {
            // �����ǰ�ڵ㲻������β��������ǰһ���ڵ����һ��ָ��
            entry->prev->next = entry->next;
        }
        else
        {
            // �����ǰ�ڵ��ǹ�ϣ���еĵ�һ��Ԫ�أ����¹�ϣ��ı�ͷָ��
            cache->table[hash] = entry->next;
        }

        if (entry->next != NULL)
        {
            // ���º�һ���ڵ��ǰһ��ָ��
            entry->next->prev = entry->prev;
        }
        else
        {
            // �����ǰ�ڵ�������β�������������βָ��
            cache->tail = entry->prev;
        }

        if (entry == cache->head)
        {
            // �����ǰ�ڵ�������ͷ�������������ͷָ��
            cache->head = entry->next;
        }

        // �ͷŵ�ǰ�ڵ���ڴ�ռ�
        free(entry);

        // ����ϣ���е�ǰ��ϣֵ��Ӧ�������Ƿ�Ϊ�գ����Ϊ����ֹͣɾ��
        if (cache->table[hash] == NULL)
        {
            break;
        }
    }
}
