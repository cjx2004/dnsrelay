#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <stdbool.h>
#include "thread_pool.h"

extern CRITICAL_SECTION threadPoolCS; // �̳߳��ٽ���
extern HANDLE semaphore;              // �ź����������̳߳غ͵ȴ�����֮���ͬ��

// ��ʼ���̳߳غ͵ȴ�����
void init_thread_pool(struct ThreadPool* pool)
{
    // ��ʼ���̳߳�
    pool->count = MAX_THREADS; //
    for (int i = 0; i < MAX_THREADS; i++)
    {
        pool->params[i] = (struct ThreadParam*)malloc(sizeof(struct ThreadParam));
        pool->params[i]->sock = (int)INVALID_SOCKET;
        pool->params[i]->trie = NULL;
        pool->params[i]->cache = NULL;
    }
    InitializeCriticalSection(&threadPoolCS);                          // ��ʼ���ٽ���
    semaphore = CreateSemaphore(NULL, MAX_THREADS, MAX_THREADS, NULL); // ��ʼ���ź���
}

// �����̳߳غ͵ȴ�����
void destroy_thread_pool(struct ThreadPool* pool)
{
    for (int i = 0; i < pool->count; i++) // �ͷ��̳߳��еĲ���
    {
        free(pool->params[i]);
    }
    DeleteCriticalSection(&threadPoolCS); // ɾ���ٽ���
    CloseHandle(semaphore);               // �ر��ź���
}

// ���DNS�����̳߳ػ�ȴ�������
void add_to_pool(struct ThreadPool* pool, struct ThreadParam* param)
{
    EnterCriticalSection(&threadPoolCS); // �����ٽ���
    if (pool->count < MAX_THREADS)       // ����̳߳����п����߳�
    {
        pool->params[pool->count++] = param;  // ��������ӵ��̳߳���
        ReleaseSemaphore(semaphore, 1, NULL); // �ͷ��ź���
    }
    LeaveCriticalSection(&threadPoolCS); // �뿪�ٽ���
}

// �߳���ں��������ڴ���DNS����
unsigned __stdcall threadProc(void* pParam)
{
    struct ThreadParam* param = (struct ThreadParam*)pParam; // ��ȡ����
    handle_dns_request(param->trie, param->cache, param->sock, param->clientAddr, param->remoteDnsAddr); // ����DNS����
    param->trie = NULL; // �ͷŲ���
    param->cache = NULL;
    param->sock = (int)INVALID_SOCKET;
    return 0;
}
