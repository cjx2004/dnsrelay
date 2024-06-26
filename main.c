#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <process.h>
#include <stdbool.h>
#include <string.h>
#include "dns_relay_server.h"
#include "thread_pool.h"

#define DEFAULT_PORT 53          // DNS������Ĭ�϶˿ں�
#define MAX_DNS_PACKET_SIZE 1024 // DNS��������󳤶�
CRITICAL_SECTION threadPoolCS;   // �̳߳��ٽ���
HANDLE semaphore;                // �ź����������̳߳غ͵ȴ�����֮���ͬ��

int cmdOption = 0;
char remoteDnsAddr[16] = "10.3.9.4"; // Ĭ�ϵ�Զ��DNS��������ַ

int main(int argc, char* argv[])
{
    // Ĭ�ϼ����˿ں�
    int port = DEFAULT_PORT;

    // ���������в���
    if (argc > 1 && strcmp(argv[2], "-d") == 0) {
        cmdOption = 1; // ����ģʽ����
        printf("����ģʽ����\n");
    }
    if (argc > 3) {
        strncpy(remoteDnsAddr, argv[3], sizeof(remoteDnsAddr) - 1);
        remoteDnsAddr[sizeof(remoteDnsAddr) - 1] = '\0'; // ȷ���ַ����� null ��β
    }

    // ��ʼ���̳߳غ͵ȴ�����
    struct ThreadPool threadPool;
    init_thread_pool(&threadPool);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("��ʼ��Winsockʧ��.\n");
        return 1;
    }

    // ����socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        printf("��������socketʧ��.\n");
        return 1;
    }

    // �󶨶˿�
    if (argc > 1)
        port = atoi(argv[1]);

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        printf("�󶨼���socket���˿�%dʧ��.\n", port);
        closesocket(sock);
        return 1;
    }

    printf("DNS�м̷��������ڼ����˿�%d.\n", port);

    // �����ֵ����ͻ����
    struct Trie* trie = (struct Trie*)malloc(sizeof(struct Trie));
    initTrie(trie);
    loadLocalTable(trie);

    struct Cache* cache = (struct Cache*)malloc(sizeof(struct Cache));
    initCache(cache);

    while (true)
    {
        // ����DNS����
        char buf[MAX_DNS_PACKET_SIZE];
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        int recvLen = recvfrom(sock, buf, MAX_DNS_PACKET_SIZE, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (recvLen == SOCKET_ERROR)
        {
            printf("����DNS����ʧ��.\n");
            continue;
        }

        printf("��������%s:%d��DNS���󣬳���Ϊ%d�ֽ�.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), recvLen);

        // ���̳߳���ȡ��һ���̣߳�����̳߳����������������ȴ�������
        WaitForSingleObject(semaphore, INFINITE);
        EnterCriticalSection(&threadPoolCS);
        struct ThreadParam* param = NULL;
        if (threadPool.count > 0)
        {
            param = threadPool.params[--threadPool.count];
        }
        LeaveCriticalSection(&threadPoolCS);

        if (param->trie == NULL)
        {
            // ����̳߳����п����̣߳��������������̴߳���
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
            // ����̳߳����������������ȴ�������
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

    // �ر�socket��������Դ
    closesocket(sock);
    free(trie);
    clearCache(cache);
    free(cache);
    // �����̳߳غ͵ȴ�����
    destroy_thread_pool(&threadPool);
    WSACleanup();

    return 0;
}
