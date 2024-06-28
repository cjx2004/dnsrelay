#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include "dns service.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define MAX_THREADS 40 // �̳߳ش�С

// �ṹ�壬���ڴ��ݸ��̵߳Ĳ���
struct ThreadParam
{
    struct Trie* trie;                // Trie���ṹ��ָ��
    struct Cache* cache;              // ����ṹ��ָ��
    int sock;                         // �׽���������
    struct sockaddr_in clientAddr;    // �ͻ��˵�ַ�ṹ��
    int clientAddrLen;                // �ͻ��˵�ַ����
    const char* remoteDnsAddr;        // Զ��DNS��������ַ
    struct ThreadParam* next;         // ��һ�����������ڹ����ȴ�����
};

// �̳߳ؽṹ��
struct ThreadPool
{
    struct ThreadParam* params[MAX_THREADS]; // �̳߳�
    int count;                 // �̳߳��п����̵߳�����
    struct ThreadParam* waiting_queue; // �ȴ�����ͷָ��
};

// ��ʼ���̳߳غ͵ȴ�����
void init_pool_of_thread(struct ThreadPool* pool);

// �����̳߳غ͵ȴ�����
void destroy_pool_of_thread(struct ThreadPool* pool);

// ���DNS�����̳߳ػ�ȴ�������
void add_pool_of_thread(struct ThreadPool* pool, struct ThreadParam* param);

// �߳���ں��������ڴ���DNS����
unsigned __stdcall threadProc(void* pParam);

#endif
