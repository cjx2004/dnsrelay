#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cache.h"
#include <WS2tcpip.h>


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
unsigned int hashCode(const unsigned char* domain)
{
    uint32_t hashValue = MurmurHash(domain, strlen((const char*)domain), 0) % CACHE_SIZE; // ���� MurmurHash �㷨�����ϣֵ
    return (unsigned int)hashValue; // ���ع�ϣֵ
}

// ���һ�����
// ��������������δ���ڣ������ƶ�������ͷ���������� IP ��ַ������ 1
// �����������ڻ��ѹ��ڣ�ɾ�����Ӧ�Ĺ�ϣ������������ 0
int findEntry(struct Cache* cache, const unsigned char* domain, unsigned char* ipAddr, int ipVersion)
{
    
    size_t domainLen = strlen((const char*)domain); // ��ȡ��������
    unsigned int hash = hashCode(domain); // ��ȡ��ϣֵ
    time_t now = time(NULL); // ��ȡ��ǰʱ��

    printf("��ʼ��cache��Ѱ��,����Ϊ��%s,��ϣֵΪ��%u \n", domain,hash);

    if (cache->head != cache->tail)
    {
        removeExpiredEntries(cache);
        return 0;
    }

    struct CacheEntry* entry = cache->table[hash];

    while (entry != NULL)
    {
        printf("�����Ӧ��ϣ����\n");
        if (entry->expireTime < 0) // ����Ѿ���ʱ
        {
            cache->table[hash] = NULL;
            return 0;
        }
        // ����ҵ��˶�Ӧ������
        if (strcmp((const char*)entry->domain, (const char*)domain) == 0)
        {
            printf("�ҵ���Ӧ������\n");
            // ���������δ����
            if (entry->expireTime >= now)
            {
                // LRU���ԣ������еĻ����ƶ�������ͷ��
                if (entry->prev != NULL) // �����������ͷ��
                    entry->prev->next = entry->next;
                else // ���������ͷ��
                    cache->head = entry->next;
                if (entry->next != NULL) // �����������β��
                    entry->next->prev = entry->prev;
                else // ���������β��
                    cache->tail = entry->prev;

                entry->expireTime = now + 60; // ���¹���ʱ��
                entry->prev = NULL;
                entry->next = cache->head;
                cache->head = entry;

                // ���� IP ��ַ
                if (ipVersion == 1)
                    memcpy(ipAddr, entry->ipAddr, sizeof(entry->ipAddr));
                else
                    memcpy(ipAddr, entry->ipAddr6, sizeof(entry->ipAddr6));

                return 1; // ���سɹ�
            }
            else // ����������ѹ���
            {
                // ������ڣ�ɾ������
                if (entry->prev != NULL) // �����������ͷ��
                    entry->prev->next = entry->next;
                else // ���������ͷ��
                    cache->table[hash] = entry->next;
                if (entry->next != NULL) // �����������β��
                    entry->next->prev = entry->prev;
                else // ���������β��
                    cache->tail = entry->prev;
                free(entry); // �ͷ��ڴ�
                return 0; // ����ʧ��
            }
        }
        entry = entry->next; // �ƶ�ָ��
    }

    return 0; // ����ʧ��
}

// ��ӻ�����
void addEntry(struct Cache* cache, const unsigned char* domain, const unsigned char* ipAddr, int ipVersion, time_t ttl)
{
    printf("���ڼ���cache...\n");
    size_t domainLen = strlen((const char*)domain); // ��ȡ��������
    unsigned int hash = hashCode(domain); // ��ȡ��ϣֵ
    time_t now = time(NULL); // ��ȡ��ǰʱ��

    // �½�������
    struct CacheEntry* entry = (struct CacheEntry*)malloc(sizeof(struct CacheEntry));
    if (entry == NULL)
        return;

    // ��������
    memcpy(entry->domain, domain, domainLen + 1);
    entry->domain[domainLen] = '\0';

    // ����IP��ַ
    unsigned char* ip = (ipVersion == 1) ? entry->ipAddr : entry->ipAddr6;
    memcpy(ip, ipAddr, (ipVersion == 1) ? sizeof(entry->ipAddr) : sizeof(entry->ipAddr6));

    
    // ���ù���ʱ��
    entry->expireTime = now + ttl;

    // ��ӵ�����ͷ��
    entry->prev = NULL;
    entry->next = cache->head;
    if (cache->head != NULL) // �������Ϊ��
        cache->head->prev = entry;
    cache->head = entry; // ��������ͷָ��
    if (cache->tail == NULL) // �������Ϊ��
        cache->tail = entry;

    // ��ӵ���ϣ��
    entry->prev = NULL;
    entry->next = cache->table[hash];
    if (cache->table[hash] != NULL)
        cache->table[hash]->prev = entry;
    cache->table[hash] = entry;
    printf("����cache�ɹ���\n");
    printCache(cache);
    // ɾ�����ڵĻ�����
    removeExpiredEntries(cache);
}

// ɾ�����ڵĻ�����
void removeExpiredEntries(struct Cache* cache)
{
    time_t now = time(NULL); // ��ȡ��ǰʱ��
    // ������β����ʼɾ�����ڵĻ�����
    struct CacheEntry* entry = cache->tail;
    while (entry != NULL && entry->expireTime < now)
    {
        struct CacheEntry* pre = entry->prev;

        // ��������ɾ�����ڵĻ�����
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
        free(entry); // �ͷ��ڴ�
        entry = cache->tail;
    }
}

// ��ջ���
void clearCache(struct Cache* cache)
{
    // ������ϣ���ͷŻ������ڴ�
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
    cache->head = NULL; // ����ͷָ���ÿ�
    cache->tail = NULL; // ����βָ���ÿ�
}

// ��ӡ��������
void printCache(struct Cache* cache)
{
    printf("-------0-------------------Cache Contents-----------------------------\n");
    for (int i = 0; i < CACHE_SIZE; i++)
    {
        struct CacheEntry* entry = cache->table[i];
        while (entry != NULL)
        {
            char ipStr[INET6_ADDRSTRLEN] = { 0 };
            if (entry->ipAddr[0] != 0)
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
            }
            printf("[%d] Domain: %s, IP: %s  ExpireTime: %ld\n", i, entry->domain, ipStr, entry->expireTime);
            entry = entry->next;
        }
    }
}