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

#define MAX_THREADS 40 // 线程池大小

// 结构体，用于传递给线程的参数
struct ThreadParam
{
    struct Trie* trie;                // Trie树结构体指针
    struct Cache* cache;              // 缓存结构体指针
    int sock;                         // 套接字描述符
    struct sockaddr_in clientAddr;    // 客户端地址结构体
    int clientAddrLen;                // 客户端地址长度
    const char* remoteDnsAddr;        // 远程DNS服务器地址
    struct ThreadParam* next;         // 下一个参数，用于构建等待队列
};

// 线程池结构体
struct ThreadPool
{
    struct ThreadParam* params[MAX_THREADS]; // 线程池
    int count;                 // 线程池中空闲线程的数量
    struct ThreadParam* waiting_queue; // 等待队列头指针
};

// 初始化线程池和等待队列
void init_pool_of_thread(struct ThreadPool* pool);

// 销毁线程池和等待队列
void destroy_pool_of_thread(struct ThreadPool* pool);

// 添加DNS请求到线程池或等待队列中
void add_pool_of_thread(struct ThreadPool* pool, struct ThreadParam* param);

// 线程入口函数，用于处理DNS请求
unsigned __stdcall threadProc(void* pParam);

#endif
