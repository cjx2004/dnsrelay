#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "thread_pool.h"

// extern在C语言中主要作用是声明外部变量或函数，允许在多个源文件中共享同一个全局变量或函数
extern CRITICAL_SECTION threadPoolCS; // 线程池临界区，critical_section
extern HANDLE semaphore;              // 信号量，用于线程池和等待队列之间的同步,handle

// 初始化线程池和等待队列
void init_pool_of_thread(struct ThreadPool* pool)
{
    // 初始化线程池参数
    pool->count = 0;
    for (int i = 0; i < MAX_THREADS; i++)
    {
        pool->params[i] = NULL;
    }

    InitializeCriticalSection(&threadPoolCS);  // 初始化临界区

    /*
     * 确保只有一个线程可以访问特定的共享资源或代码块，以避免数据竞争和不一致性。
     * InitializeCriticalSection 用于初始化一个临界区对象，它的作用是在多线程环境中保护共享资源
     * （例如，ThreadPool 结构体中的参数数组）不被多个线程同时访问。
     */

    semaphore = CreateSemaphore(NULL, MAX_THREADS, MAX_THREADS, NULL); // 初始化信号量
    /*
     * 信号量（Semaphore）是多线程编程中的一种同步机制，用于控制对共享资源的访问。
     * CreateSemaphore 函数用于初始化信号量，以便在多线程环境中管理资源的并发访问。
     */
}

// 销毁线程池和等待队列
void destroy_pool_of_thread(struct ThreadPool* pool)
{
    // 释放每个线程参数的内存
    for (int i = 0; i < pool->count; i++)
    {
        free(pool->params[i]);
    }

    DeleteCriticalSection(&threadPoolCS); // 删除临界区
    CloseHandle(semaphore);               // 关闭信号量
}

// 添加DNS请求到线程池或等待队列中
void add_pool_of_thread(struct ThreadPool* pool, struct ThreadParam* param)
{
    EnterCriticalSection(&threadPoolCS); // 进入临界区

    // 如果线程池中有空闲线程，则直接将参数添加到线程池中
    if (pool->count < MAX_THREADS)
    {
        pool->params[pool->count++] = param;  // 将参数添加到线程池中
        ReleaseSemaphore(semaphore, 1, NULL); // 释放信号量，表示有新的任务可以执行
    }
    else //放入等待序列
    {
        // 如果线程池已满，则将参数加入等待队列中（这里假设等待队列为一个简单的链表）
        if (pool->waiting_queue == NULL)
        {
            pool->waiting_queue = param; // 队列为空时，直接添加到队列头部
        }
        else
        {
            // 找到队列尾部，将参数添加到队列末尾
            struct ThreadParam* current = pool->waiting_queue;
            while (current->next != NULL)
            {
                current = current->next;
            }
            current->next = param;
        }
    }

    LeaveCriticalSection(&threadPoolCS); // 离开临界区
}

// 线程入口函数，用于处理DNS请求
unsigned __stdcall threadProc(void* pParam)
{
    struct ThreadParam* param = (struct ThreadParam*)pParam; // 获取参数
    handle_dns_request(param->trie, param->cache, param->sock, param->clientAddr, param->remoteDnsAddr); // 处理DNS请求
    param->trie = NULL; // 释放参数
    param->cache = NULL;
    param->sock = (int)INVALID_SOCKET;
    return 0;
}
