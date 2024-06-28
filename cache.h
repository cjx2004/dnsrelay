#ifndef CACHE_H
#define CACHE_H

#include <time.h>
#include "murmurhash.h"

#define CACHE_SIZE 1000

// 缓存项结构体
struct CacheEntry
{
    unsigned char domain[512]; // 域名
    unsigned char ipAddr[16];  // IPv4 地址
    unsigned char ipAddr6[40]; // IPv6 地址
    time_t expireTime;         // 过期时间
    struct CacheEntry* prev;   // 前驱指针
    struct CacheEntry* next;   // 后继指针
};

// 缓存结构体
struct Cache
{
    struct CacheEntry* table[CACHE_SIZE]; // 哈希表
    struct CacheEntry* head;              // 链表头指针
    struct CacheEntry* tail;              // 链表尾指针
};

// 初始化缓存
void initCache(struct Cache* cache);

// 计算哈希值
unsigned int calculateHash(const unsigned char* domain);

// 查找缓存项
int retrieveCacheEntry(struct Cache* cache, const unsigned char* domain, unsigned char* ipAddr, int ipVersion);

// 添加缓存项
void insertCacheEntry(struct Cache* cache, const unsigned char* domain, const unsigned char* ipAddr, int ipVersion, time_t ttl);

// 删除缓存项
void purgeExpiredEntries(struct Cache* cache);

// 清空缓存
void clearCacheEntries(struct Cache* cache);

// 打印缓存内容
void printCache(struct Cache* cache);

//删除最远不用的表项
void removeLeastRecentlyUsed(struct Cache* cache);

#endif /* CACHE_H */