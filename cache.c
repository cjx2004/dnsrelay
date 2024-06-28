#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cache.h"
#include <WS2tcpip.h>

/*哈希表的查找效率为O(1)，链表的遍历是O(N)，
LRU 缓存策略中的主要操作（访问、添加、淘汰）都可以在 O(1) 时间复杂度内完成，这得益于哈希表和双向链表的结合使用
*/

/*LRU思路：
将最新访问的cache表项移到链表开头，cache满后从后开始删除cache表项
*/

// 初始化缓存
void initCache(struct Cache* cache)
{
    memset(cache->table, 0, sizeof(cache->table)); // 将哈希表清零
    cache->head = NULL; // 链表头指针置空
    cache->tail = NULL; // 链表尾指针置空
}

// 计算哈希值
unsigned int calculateHash(const unsigned char* domain)
{
    if (domain == NULL) {
        printf("Error: Domain is NULL!\n");
        return 0;
    }
    uint32_t hashValue = MurmurHash(domain, strlen((const char*)domain), 0) % CACHE_SIZE;
    return (unsigned int)hashValue;
}

// 添加缓存项
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

// 删除过期的缓存项
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

// 清空缓存
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

// 查找缓存项
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


// 打印缓存内容
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
                // 打印IPv4地址
                snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", entry->ipAddr[0], entry->ipAddr[1], entry->ipAddr[2], entry->ipAddr[3]);
            }
            else if (entry->ipAddr6[0] != 0)
            {
                // 打印IPv6地址
                
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

// 删除最久未使用的缓存项
void removeLeastRecentlyUsed(struct Cache* cache)
{
    while (cache->tail != NULL)
    {
        // 从链表尾部删除最久未使用的缓存项
        struct CacheEntry* entry = cache->tail;
        unsigned int hash = calculateHash(entry->domain); // 计算域名的哈希值

        // 从哈希表中删除当前节点
        if (entry->prev != NULL)
        {
            // 如果当前节点不是链表尾部，更新前一个节点的下一个指针
            entry->prev->next = entry->next;
        }
        else
        {
            // 如果当前节点是哈希表中的第一个元素，更新哈希表的表头指针
            cache->table[hash] = entry->next;
        }

        if (entry->next != NULL)
        {
            // 更新后一个节点的前一个指针
            entry->next->prev = entry->prev;
        }
        else
        {
            // 如果当前节点是链表尾部，更新链表的尾指针
            cache->tail = entry->prev;
        }

        if (entry == cache->head)
        {
            // 如果当前节点是链表头部，更新链表的头指针
            cache->head = entry->next;
        }

        // 释放当前节点的内存空间
        free(entry);

        // 检查哈希表中当前哈希值对应的链表是否为空，如果为空则停止删除
        if (cache->table[hash] == NULL)
        {
            break;
        }
    }
}
