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

#define DEFAULT_PORT 53          // DNS������Ĭ�϶˿ں�
#define MAX_DNS_PACKET_SIZE 1024 // DNS��������󳤶�
CRITICAL_SECTION threadPoolCS;   // �̳߳��ٽ���
HANDLE semaphore;                // �ź����������̳߳غ͵ȴ�����֮���ͬ��

int cmdOption = 0;
char remoteDnsAddr[16] = "10.3.9.5"; // Ĭ�ϵ�Զ��DNS��������ַ

int main(int argc, char* argv[])
{
    // Ĭ�ϼ����˿ں�
    int port = DEFAULT_PORT;

    // ���������в���
    if (argc > 1 && strcmp(argv[2], "-d") == 0) {
        cmdOption = 1; // ����ģʽ����
        port = atoi(argv[1]); // �󶨶˿�
        printf("����ģʽ����\n");
    }
    if (argc > 3) {
        strncpy(remoteDnsAddr, argv[3], sizeof(remoteDnsAddr) - 1);
        remoteDnsAddr[sizeof(remoteDnsAddr) - 1] = '\0'; // ȷ���ַ����� null ��β
    }

    /*
    * Winsock��Windows Sockets���� Windows ����ϵͳ����������ͨ�ŵı�̽ӿڣ�
      ���ṩ��һ���׼�� API��ʹ�����߿�����Ӧ�ó�����ʵ������ͨ�Ź��ܡ�
    */
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("��ʼ��Winsockʧ��.\n");
        return 1;
    }

    

    // ��ʼ���̳߳غ͵ȴ�����
    struct ThreadPool threadPool;
    init_thread_pool(&threadPool);

    // ����socket
    /*
    * sock ��һ���׽��֣�Socket������������������һ������ֵ�����ڱ�ʶһ������ͨ�Ŷ˵㡣
    */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);


    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;//Ĭ��ipv4
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);//IP ��ַ��ʹ�� htonl �����������ֽ���ת��Ϊ�����ֽ���INADDR_ANY ��ʾ�󶨵����п��õ�����ӿڡ�
    
    // ��Ŀ���豸��IP��ַת��Ϊ��������ʽ������ֵ��serverAddr.sin_addr
    /*if (inet_pton(AF_INET, "10.129.42.104", &serverAddr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    } */
    if (bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        printf("�󶨼���socket���˿�%dʧ��.\n", port);
        closesocket(sock);
        printf("�ر�socket����.\n", port);
        return 1;
    }

    printf("DNS�м̷��������ڼ����˿�%d.\n", port);

    // �����ֵ����ͻ����
    struct Trie* trie = (struct Trie*)malloc(sizeof(struct Trie));
    initTrie(trie); //�����ֵ���
    loadLocalTable(trie); //�ֵ�������ֵ

    struct Cache* cache = (struct Cache*)malloc(sizeof(struct Cache)); //����cache
    initCache(cache);

    while (true)
    {
        // ����DNS����
        char buf[MAX_DNS_PACKET_SIZE]; //����һ�������� buf ���洢���յ�������
        struct sockaddr_in clientAddr; //�洢�ͻ��˵ĵ�ַ��Ϣ
        int clientAddrLen = sizeof(clientAddr);

        // ���� recvfrom ������������
        int recvinfo = recvfrom(sock, buf, MAX_DNS_PACKET_SIZE, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        //�Զ�����ͻ��˵�ַ
        if (recvinfo == SOCKET_ERROR)
        {
            printf("����DNS����ʧ��.\n");
            continue;
        }

        // ��ӡ���յ���DNS������Ϣ
        printf("��������%s:%d��DNS���󣬳���Ϊ%d�ֽ�.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), recvinfo);

        // ���̳߳���ȡ��һ���̣߳�����̳߳����������������ȴ�������

        //�ȴ��̳߳����п��õ��߳�
        WaitForSingleObject(semaphore, INFINITE);
        EnterCriticalSection(&threadPoolCS);
        struct ThreadParam* param = NULL;

        //���̳߳��л�ȡһ����������
        if (threadPool.count > 0)
        {
            param = threadPool.params[--threadPool.count];
        }

        //�뿪�ٽ��� (LeaveCriticalSection) �ͷŶԹ�����Դ�ı���
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
