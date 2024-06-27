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
unsigned int hashCode(const unsigned char* domain)
{
    if (domain == NULL) {
        printf("差错处理：域名为空，发生错误！\n");
        return 0;
    }
    uint32_t hashValue = MurmurHash(domain, strlen((const char*)domain), 0) % CACHE_SIZE; // 调用 MurmurHash 算法计算哈希值
    return (unsigned int)hashValue; // 返回哈希值
}


// 添加缓存项
void addEntry(struct Cache* cache, const unsigned char* domain, const unsigned char* ipAddr, int ipVersion, time_t ttl)
{
    if (domain == NULL) {
        printf("差错处理：域名为空，发生错误！\n");
        return ;
    }
    printf("正在加入cache...\n");
    size_t domainLen = strlen((const char*)domain); // 获取域名长度
    unsigned int hash = hashCode(domain); // 获取哈希值
    time_t now = time(NULL); // 获取当前时间

    // 新建缓存项
    struct CacheEntry* entry = (struct CacheEntry*)malloc(sizeof(struct CacheEntry));
    if (entry == NULL) {
        printf("内存分配失败!\n");
        return;
    }       

    // 复制域名
    memcpy(entry->domain, domain, domainLen + 1);
    entry->domain[domainLen] = '\0';

    // 复制IP地址
    if (ipVersion == 1) {
        memcpy(entry->ipAddr, ipAddr, sizeof(entry->ipAddr));
    }
    else if (ipVersion == 28) {
        memcpy(entry->ipAddr6, ipAddr, sizeof(entry->ipAddr6));
    }
    else {
        // 无效的 IP 版本，差错处理
        printf("ip地址出错!\n");
        free(entry);
        return;
    }

    // 设置过期时间
    entry->expireTime = now + ttl;

    // 检查缓存是否已满，如果满了，按照LRU策略删除最久未使用的缓存项
    int isfull = 1;
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache->table[i] == NULL) {
            //未满
            isfull = 0;
            break;
        }
        else {

            removeLeastRecentlyUsed(cache);
        }
    }

    // 添加到链表头部
    entry->prev = NULL;
    entry->next = cache->head;
    if (cache->head != NULL) // 如果链表不为空
        cache->head->prev = entry;
    cache->head = entry; // 更新链表头指针
    if (cache->tail == NULL) // 如果链表为空
        cache->tail = entry;

    // 添加到哈希表
    entry->prev = NULL;
    entry->next = cache->table[hash];
    if (cache->table[hash] != NULL)
        cache->table[hash]->prev = entry;
    cache->table[hash] = entry;
    printf("加入cache成功！\n");
    //printCache(cache);
    // 删除过期的缓存项
    removeExpiredEntries(cache);
}

// 删除过期的缓存项
void removeExpiredEntries(struct Cache* cache)
{
    time_t now = time(NULL); // 获取当前时间
    // 从链表尾部开始删除过期的缓存项
    struct CacheEntry* entry = cache->tail;
    while (entry != NULL && entry->expireTime < now)
    {
        struct CacheEntry* pre = entry->prev;

        // 从链表中删除过期的缓存项
        if (pre != NULL)
        {
            pre->next = NULL;
            cache->tail = pre;
        }
        else
        {
            cache->tail = NULL;
            cache->head = NULL;
        }
        free(entry); // 释放内存
        entry = cache->tail;
    }
}

// 清空缓存
void clearCache(struct Cache* cache)
{
    // 遍历哈希表，释放缓存项内存
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
    cache->head = NULL; // 链表头指针置空
    cache->tail = NULL; // 链表尾指针置空
}

// 查找缓存项
// 如果缓存项存在且未过期，将其移动到链表头部，并设置 IP 地址，返回 1
// 如果缓存项不存在或已过期，删除其对应的哈希表和链表项，返回 0
int findEntry(struct Cache* cache, const unsigned char* domain, unsigned char* ipAddr, int ipVersion)
{

    size_t domainLen = strlen((const char*)domain); // 获取域名长度
    unsigned int hash = hashCode(domain); // 获取哈希值
    time_t now = time(NULL); // 获取当前时间

    printf("开始在cache中寻找,域名为：%s,哈希值为：%u \n", domain, hash);


    struct CacheEntry* entry = cache->table[hash];

    while (entry != NULL)
    {
        printf("进入对应哈希格了\n");
        if (entry->expireTime < 0) // 如果已经超时
        {
            cache->table[hash] = NULL;
            return 0;
        }
        if (cache->head != cache->tail)
        {
            removeExpiredEntries(cache);
            printf("在缓存表查找成功,域名为%s\n", domain);
            return 0;
        }
        // 如果找到了对应的域名
        if (strcmp((const char*)entry->domain, (const char*)domain) == 0 && ((ipVersion==1 && entry->ipAddr != NULL) || (ipVersion == 28 && entry->ipAddr6 != NULL)))
        {
            printf("找到对应域名！\n");
            // 如果缓存项未过期
            if (entry->expireTime >= now)
            {
                // LRU策略，将命中的缓存移动到链表头部
                if (entry->prev != NULL) // 如果不是链表头部
                    entry->prev->next = entry->next;
                else // 如果是链表头部
                    cache->head = entry->next;
                if (entry->next != NULL) // 如果不是链表尾部
                    entry->next->prev = entry->prev;
                else // 如果是链表尾部
                    cache->tail = entry->prev;

                entry->expireTime = now + 60; // 更新过期时间
                entry->prev = NULL;
                entry->next = cache->head;
                cache->head = entry;

                // 设置 IP 地址
                if (ipVersion == 1)
                    memcpy(ipAddr, entry->ipAddr, sizeof(entry->ipAddr));
                else
                    memcpy(ipAddr, entry->ipAddr6, sizeof(entry->ipAddr6));

                return 1; // 返回成功
            }
            else // 如果缓存项已过期
            {
                // 缓存过期，删除缓存
                if (entry->prev != NULL) // 如果不是链表头部
                    entry->prev->next = entry->next;
                else // 如果是链表头部
                    cache->table[hash] = entry->next;
                if (entry->next != NULL) // 如果不是链表尾部
                    entry->next->prev = entry->prev;
                else // 如果是链表尾部
                    cache->tail = entry->prev;
                free(entry); // 释放内存
                return 0; // 返回失败
            }
        }
        entry = entry->next; // 移动指针
    }

    return 0; // 返回失败
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
        unsigned int hash = hashCode(entry->domain); // 计算域名的哈希值

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
