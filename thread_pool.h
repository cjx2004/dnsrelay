#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <stdbool.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <stdbool.h>
#include "dns_relay_server.h"

#define MAX_THREADS 40 // �̳߳ش�С

// �ṹ��,���ڴ��ݸ��̵߳Ĳ���
struct ThreadParam
{
    struct Trie* trie;
    struct Cache* cache;
    int sock;
    struct sockaddr_in clientAddr;
    int clientAddrLen;
    const char* remoteDnsAddr;
};

// �̳߳ؽṹ��
struct ThreadPool
{
    struct ThreadParam* params[MAX_THREADS]; // �̳߳�
    int count;                 // �̳߳��п����̵߳�����
};

// ��ʼ���̳߳غ͵ȴ�����
void init_thread_pool(struct ThreadPool* pool);

// �����̳߳غ͵ȴ�����
void destroy_thread_pool(struct ThreadPool* pool);

// ���DNS�����̳߳ػ�ȴ�������
void add_to_pool(struct ThreadPool* pool, struct ThreadParam* param);

// �߳���ں��������ڴ���DNS����
unsigned __stdcall threadProc(void* pParam);

#endif