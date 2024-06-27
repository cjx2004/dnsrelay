#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <stdbool.h>
#include <string.h>
#include "dns_relay_server.h"
#include "thread_pool.h"

#ifdef _WIN32
#include <Winsock2.h>
#include <windows.h>
// Windows-specific code
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// Linux-specific code
#endif

#define DEFAULT_PORT 53          // DNS服务器默认端口号
#define MAX_DNS_PACKET_SIZE 1024 // DNS请求报文最大长度
CRITICAL_SECTION threadPoolCS;   // 线程池临界区
HANDLE semaphore;                // 信号量，用于线程池和等待队列之间的同步

int cmdOption = 0;
char remoteDnsAddr[16] = "10.3.9.5"; // 默认的远程DNS服务器地址

int main(int argc, char* argv[])
{
    // 默认监听端口号
    int port = DEFAULT_PORT;

    // 处理命令行参数
    if (argc > 1 && strcmp(argv[2], "-d") == 0) {
        cmdOption = 1; // 调试模式启动
        port = atoi(argv[1]); // 绑定端口
        printf("调试模式启动\n");
    }
    if (argc > 3) {
        strncpy(remoteDnsAddr, argv[3], sizeof(remoteDnsAddr) - 1);
        remoteDnsAddr[sizeof(remoteDnsAddr) - 1] = '\0'; // 确保字符串以 null 结尾
    }

    /*
    * Winsock（Windows Sockets）是 Windows 操作系统上用于网络通信的编程接口，
      它提供了一组标准的 API，使开发者可以在应用程序中实现网络通信功能。
    */
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("初始化Winsock失败.\n");
        return 1;
    }

    

    // 初始化线程池和等待队列
    struct ThreadPool threadPool;
    init_thread_pool(&threadPool);

    // 创建socket
    /*
    * sock 是一个套接字（Socket）描述符或句柄，它是一个整数值，用于标识一个网络通信端点。
    */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);


    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;//默认ipv4
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);//IP 地址，使用 htonl 函数将主机字节序转换为网络字节序。INADDR_ANY 表示绑定到所有可用的网络接口。
    
    // 将目标设备的IP地址转换为二进制形式，并赋值给serverAddr.sin_addr
    /*if (inet_pton(AF_INET, "10.129.42.104", &serverAddr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    } */
    if (bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        printf("绑定监听socket到端口%d失败.\n", port);
        closesocket(sock);
        printf("关闭socket连接.\n", port);
        return 1;
    }

    printf("DNS中继服务器正在监听端口%d.\n", port);

    // 创建字典树和缓存表
    struct Trie* trie = (struct Trie*)malloc(sizeof(struct Trie));
    initTrie(trie); //创建字典树
    loadLocalTable(trie); //字典树附初值

    struct Cache* cache = (struct Cache*)malloc(sizeof(struct Cache)); //创建cache
    initCache(cache);

    while (true)
    {
        // 接收DNS请求
        char buf[MAX_DNS_PACKET_SIZE]; //分配一个缓冲区 buf 来存储接收到的数据
        struct sockaddr_in clientAddr; //存储客户端的地址信息
        int clientAddrLen = sizeof(clientAddr);

        // 调用 recvfrom 函数接收数据
        int recvinfo = recvfrom(sock, buf, MAX_DNS_PACKET_SIZE, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        //自动分配客户端地址
        if (recvinfo == SOCKET_ERROR)
        {
            printf("接收DNS请求失败.\n");
            continue;
        }

        // 打印接收到的DNS请求信息
        printf("接收来自%s:%d的DNS请求，长度为%d字节.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), recvinfo);

        // 从线程池中取出一个线程，如果线程池已满，则将请求放入等待队列中

        //等待线程池中有可用的线程
        WaitForSingleObject(semaphore, INFINITE);
        EnterCriticalSection(&threadPoolCS);
        struct ThreadParam* param = NULL;

        //从线程池中获取一个任务或参数
        if (threadPool.count > 0)
        {
            param = threadPool.params[--threadPool.count];
        }

        //离开临界区 (LeaveCriticalSection) 释放对共享资源的保护
        LeaveCriticalSection(&threadPoolCS);

        if (param->trie == NULL)
        {
            // 如果线程池中有空闲线程，则将请求分配给该线程处理
            param->trie = trie;
            param->cache = cache;
            param->sock = sock;
            param->clientAddr = clientAddr;
            param->clientAddrLen = clientAddrLen;
            param->remoteDnsAddr = remoteDnsAddr;
            _beginthreadex(NULL, 0, threadProc, param, 0, NULL);
        }
        else
        {
            // 如果线程池已满，则将请求放入等待队列中
            param = (struct ThreadParam*)malloc(sizeof(struct ThreadParam));
            param->trie = trie;
            param->cache = cache;
            param->sock = sock;
            param->clientAddr = clientAddr;
            param->clientAddrLen = clientAddrLen;
            param->remoteDnsAddr = remoteDnsAddr;

            EnterCriticalSection(&threadPoolCS);
            add_to_pool(&threadPool, param);
            LeaveCriticalSection(&threadPoolCS);
        }
    }

    // 关闭socket和清理资源
    closesocket(sock);
    free(trie);
    clearCache(cache);
    free(cache);
    // 销毁线程池和等待队列
    destroy_thread_pool(&threadPool);
    WSACleanup();

    return 0;
}
