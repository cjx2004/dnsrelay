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
unsigned int hashCode(const unsigned char* domain)
{
    if (domain == NULL) {
        printf("���������Ϊ�գ���������\n");
        return 0;
    }
    uint32_t hashValue = MurmurHash(domain, strlen((const char*)domain), 0) % CACHE_SIZE; // ���� MurmurHash �㷨�����ϣֵ
    return (unsigned int)hashValue; // ���ع�ϣֵ
}


// ��ӻ�����
void addEntry(struct Cache* cache, const unsigned char* domain, const unsigned char* ipAddr, int ipVersion, time_t ttl)
{
    if (domain == NULL) {
        printf("���������Ϊ�գ���������\n");
        return ;
    }
    printf("���ڼ���cache...\n");
    size_t domainLen = strlen((const char*)domain); // ��ȡ��������
    unsigned int hash = hashCode(domain); // ��ȡ��ϣֵ
    time_t now = time(NULL); // ��ȡ��ǰʱ��

    // �½�������
    struct CacheEntry* entry = (struct CacheEntry*)malloc(sizeof(struct CacheEntry));
    if (entry == NULL) {
        printf("�ڴ����ʧ��!\n");
        return;
    }       

    // ��������
    memcpy(entry->domain, domain, domainLen + 1);
    entry->domain[domainLen] = '\0';

    // ����IP��ַ
    if (ipVersion == 1) {
        memcpy(entry->ipAddr, ipAddr, sizeof(entry->ipAddr));
    }
    else if (ipVersion == 28) {
        memcpy(entry->ipAddr6, ipAddr, sizeof(entry->ipAddr6));
    }
    else {
        // ��Ч�� IP �汾�������
        printf("ip��ַ����!\n");
        free(entry);
        return;
    }

    // ���ù���ʱ��
    entry->expireTime = now + ttl;

    // ��黺���Ƿ�������������ˣ�����LRU����ɾ�����δʹ�õĻ�����
    int isfull = 1;
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (cache->table[i] == NULL) {
            //δ��
            isfull = 0;
            break;
        }
        else {

            removeLeastRecentlyUsed(cache);
        }
    }

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
    //printCache(cache);
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

// ���һ�����
// ��������������δ���ڣ������ƶ�������ͷ���������� IP ��ַ������ 1
// �����������ڻ��ѹ��ڣ�ɾ�����Ӧ�Ĺ�ϣ������������ 0
int findEntry(struct Cache* cache, const unsigned char* domain, unsigned char* ipAddr, int ipVersion)
{

    size_t domainLen = strlen((const char*)domain); // ��ȡ��������
    unsigned int hash = hashCode(domain); // ��ȡ��ϣֵ
    time_t now = time(NULL); // ��ȡ��ǰʱ��

    printf("��ʼ��cache��Ѱ��,����Ϊ��%s,��ϣֵΪ��%u \n", domain, hash);


    struct CacheEntry* entry = cache->table[hash];

    while (entry != NULL)
    {
        printf("�����Ӧ��ϣ����\n");
        if (entry->expireTime < 0) // ����Ѿ���ʱ
        {
            cache->table[hash] = NULL;
            return 0;
        }
        if (cache->head != cache->tail)
        {
            removeExpiredEntries(cache);
            printf("�ڻ������ҳɹ�,����Ϊ%s\n", domain);
            return 0;
        }
        // ����ҵ��˶�Ӧ������
        if (strcmp((const char*)entry->domain, (const char*)domain) == 0 && ((ipVersion==1 && entry->ipAddr != NULL) || (ipVersion == 28 && entry->ipAddr6 != NULL)))
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
        unsigned int hash = hashCode(entry->domain); // ���������Ĺ�ϣֵ

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
