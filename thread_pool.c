#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "thread_pool.h"

// extern��C��������Ҫ�����������ⲿ���������������ڶ��Դ�ļ��й���ͬһ��ȫ�ֱ�������
extern CRITICAL_SECTION threadPoolCS; // �̳߳��ٽ�����critical_section
extern HANDLE semaphore;              // �ź����������̳߳غ͵ȴ�����֮���ͬ��,handle

// ��ʼ���̳߳غ͵ȴ�����
void init_pool_of_thread(struct ThreadPool* pool)
{
    // ��ʼ���̳߳ز���
    pool->count = 0;
    for (int i = 0; i < MAX_THREADS; i++)
    {
        pool->params[i] = NULL;
    }

    InitializeCriticalSection(&threadPoolCS);  // ��ʼ���ٽ���

    /*
     * ȷ��ֻ��һ���߳̿��Է����ض��Ĺ�����Դ�����飬�Ա������ݾ����Ͳ�һ���ԡ�
     * InitializeCriticalSection ���ڳ�ʼ��һ���ٽ������������������ڶ��̻߳����б���������Դ
     * �����磬ThreadPool �ṹ���еĲ������飩��������߳�ͬʱ���ʡ�
     */

    semaphore = CreateSemaphore(NULL, MAX_THREADS, MAX_THREADS, NULL); // ��ʼ���ź���
    /*
     * �ź�����Semaphore���Ƕ��̱߳���е�һ��ͬ�����ƣ����ڿ��ƶԹ�����Դ�ķ��ʡ�
     * CreateSemaphore �������ڳ�ʼ���ź������Ա��ڶ��̻߳����й�����Դ�Ĳ������ʡ�
     */
}

// �����̳߳غ͵ȴ�����
void destroy_pool_of_thread(struct ThreadPool* pool)
{
    // �ͷ�ÿ���̲߳������ڴ�
    for (int i = 0; i < pool->count; i++)
    {
        free(pool->params[i]);
    }

    DeleteCriticalSection(&threadPoolCS); // ɾ���ٽ���
    CloseHandle(semaphore);               // �ر��ź���
}

// ���DNS�����̳߳ػ�ȴ�������
void add_pool_of_thread(struct ThreadPool* pool, struct ThreadParam* param)
{
    EnterCriticalSection(&threadPoolCS); // �����ٽ���

    // ����̳߳����п����̣߳���ֱ�ӽ�������ӵ��̳߳���
    if (pool->count < MAX_THREADS)
    {
        pool->params[pool->count++] = param;  // ��������ӵ��̳߳���
        ReleaseSemaphore(semaphore, 1, NULL); // �ͷ��ź�������ʾ���µ��������ִ��
    }
    else //����ȴ�����
    {
        // ����̳߳��������򽫲�������ȴ������У��������ȴ�����Ϊһ���򵥵�����
        if (pool->waiting_queue == NULL)
        {
            pool->waiting_queue = param; // ����Ϊ��ʱ��ֱ����ӵ�����ͷ��
        }
        else
        {
            // �ҵ�����β������������ӵ�����ĩβ
            struct ThreadParam* current = pool->waiting_queue;
            while (current->next != NULL)
            {
                current = current->next;
            }
            current->next = param;
        }
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
