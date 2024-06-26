#include "dns_relay_server.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_DNS_PACKET_SIZE 1024 // DNS��������󳤶�

extern int cmdOption;

// ͨ���̳߳ز�������DNS����
void handle_dns_request(struct Trie* trie, struct Cache* cache, SOCKET sock, struct sockaddr_in clientAddr, const char* remoteDnsAddr)
{
    unsigned short offset = 0;
    unsigned char buf[MAX_DNS_PACKET_SIZE]; // �յ���DNS�����ֽ���

    // �� char �������е����ݸ��Ƶ� unsigned char ��������
    // memcpy(buf, recvBuf, len);
    // ����DNS����
    while (1)
    {
        // ���������û��˵�DNS�����ֽ���
        int clientAddrLen = sizeof(clientAddr);
        int len = recvfrom(sock, (char*)buf, MAX_DNS_PACKET_SIZE, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);

        //����
        printf("recev from %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        //

        if (len == SOCKET_ERROR)
        {
            printf("����DNS����ʧ��.\n");
            continue;
        }
        Dns_Msg* msg = NULL;
        offset = 0;
        msg = bytestream_to_dnsmsg(buf, &offset);

        cmdOption == 1 ? bytestreamInfo(buf) : (void)0; // ��ӡDNS�����ĵ��ֽ���
        cmdOption == 1 ? debug(msg) : (void)0;     // ��ӡDNS�����ĵĽṹ��

        if (msg->header->qr == 0 && msg->header->opcode == 0) // ֻ����DNS������
        {
            unsigned char domain[MAX_DOMAIN_LENGTH];
            transDN(msg->question->qname, domain); // ȡ������
            printf("�յ������û��˵�DNS����,����Ϊ%s\n", domain);

            unsigned char* ipAddress = findIpAddress(trie, cache, domain); // ����������Ӧ��IP��ַ

            if (ipAddress != NULL && ((ipAddress[4] == '\0' && msg->question->qtype == TYPE_A) || (ipAddress[4] != '\0' && msg->question->qtype == TYPE_AAAA)))                                         // ����ҵ���,����DNS��Ӧ����
            {
                printf("�м̷��������ҳɹ�,����Ϊ%s,IP��ַΪ%d.%d.%d.%d\n", domain, ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
                //���ع�������ʵ��
                addAnswer(msg, ipAddress, 60, msg->question->qtype);    // ��IP��ַ��ӵ�DNS��Ӧ������
                send_dns_response(sock, msg, clientAddr); // ����DNS��Ӧ����
            }
            else // ���û�ҵ�,��ת��DNS�����ĸ�Զ��DNS������
            {
                printf("�м̷���������ʧ��,ת��DNS�����ĸ�Զ��DNS������\n");

                // ��id�Ϳͻ��˰�,�����µ�id
                unsigned short newId = trans_port_id(msg->header->id, clientAddr);
                buf[0] = newId >> 8;
                buf[1] = newId;

                forward_dns_request(sock, buf, len, remoteDnsAddr); // ת��DNS�����ĸ�Զ��DNS������
            }
        }
        else if (msg->header->qr == 1) // �����Զ��DNS���������ص�DNS��Ӧ����
        {
            printf("�յ�����Զ��DNS��������DNS��Ӧ����\n");
            unsigned char domain[MAX_DOMAIN_LENGTH];
            unsigned char ipAddr[16];
            unsigned int ttl;
            unsigned short type;
            getDN_IP(buf, domain, ipAddr, &ttl, &type);
            addEntry(cache, domain, ipAddr, type, ttl);

            const struct sockaddr_in result = find_clientAddr(msg->header->id); // ͨ��id�ҵ��ͻ��˵�ַ
            unsigned short preId = find_id(msg->header->id);                    // ͨ��id�ҵ�ԭʼid
            buf[0] = preId >> 8;
            buf[1] = preId;

            forward_dns_response(sock, buf, len, result); // ת��DNS��Ӧ���ĸ��û���
        }
        else // ֱ��ת��DNS���ĸ�Զ��DNS������
        {
            unsigned short newId = trans_port_id(msg->header->id, clientAddr);
            buf[0] = newId >> 8;
            buf[1] = newId;

            forward_dns_request(sock, buf, len, remoteDnsAddr); // ת��DNS�����ĸ�Զ��DNS������
        }

        removeExpiredEntries(cache); // ÿ�δ�����һ��DNS����,ɾ�����ڵĻ����¼
        releaseMsg(msg);             // �ͷ�DNS����
    }
}


// ����������Ӧ��IP��ַ
unsigned char* findIpAddress(struct Trie* trie, struct Cache* cache, unsigned char domain[MAX_DOMAIN_LENGTH])
{
    unsigned char ipAddr[16];
    unsigned char* ipAddress = NULL;

    // ���ڻ�����в���,�ҵ�����
    if (findEntry(cache, domain, ipAddr, 1))
    {
        printf("�ڻ������ҳɹ�,����Ϊ%s,IPv4��ַΪ%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);
        ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 4);
        memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 4);
        ipAddress[4] = '\0';
    }
    else if (findEntry(cache, domain, ipAddr, 28))
    {
        printf("�ڻ������ҳɹ�,����Ϊ%s,IPv6��ַΪ%d.%d.%d.%d.%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3], ipAddr[4], ipAddr[5], ipAddr[6], ipAddr[7]);
        ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 16);
        memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 16);
    }
    else
    {
        // ����ڱ��ر����ҵ��˼�¼,������ӵ��������
        int node = findNode(trie, domain);
        if (node != 0)
        {
            memcpy(ipAddr, trie->toIp[node], sizeof(ipAddr));
            //addEntry(cache, domain, ipAddr, 1, CACHE_TTL);
            //addEntry(cache, domain, ipAddr, 28, CACHE_TTL);
            printf("�ڱ����ֵ������ҳɹ�,����Ϊ%s,IP��ַΪ%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);
            ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 5);
            memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 5);
            ipAddress[4] = '\0';
        }
        else // ���ر�ͻ����û���ҵ�,��Ҫת����Զ��DNS������
        {
            printf("���ر�ͻ����δ���ҵ�����%s,��Ҫ����Զ��DNS������\n", domain);
            return NULL;
        }
    }
    return ipAddress;
}

// ת��DNS�����ĸ�Զ��DNS������
void forward_dns_request(int sock, unsigned char* buf, int len, const char* remoteDnsAddr)
{
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(struct sockaddr_in));
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_addr.s_addr = inet_addr(remoteDnsAddr); // Զ��DNS��������ַ
    remoteAddr.sin_port = htons(53);                     // DNS�������˿ں�

    // ��Զ��DNS����������DNS������
    int ret = sendto(sock, (char*)buf, len, 0, (struct sockaddr*)&remoteAddr, sizeof(struct sockaddr_in));
    if (ret == SOCKET_ERROR)
        printf("sendto failed with error: %d\n", WSAGetLastError());
    else
    {
        cmdOption == 1 ? bytestreamInfo(buf) : (void)0; // ��ӡbytestream��Ϣ
        printf("��Զ��DNS����������DNS�����ĳɹ�\n");
    }
}


// ���û��˷���DNS��Ӧ����
void send_dns_response(int sock, Dns_Msg* msg, struct sockaddr_in clientAddr)
{
    unsigned char* bytestream = dnsmsg_to_bytestream(msg);
    if (bytestream == NULL) {
        printf("Failed to convert DNS message to bytestream.\n");
        return;
    }

    int len = 0;
    // ����bytestream�ĳ���
    Dns_Msg* temp = bytestream_to_dnsmsg(bytestream, (unsigned short*)(&len));
    if (temp == NULL) {
        printf("Failed to parse bytestream back to DNS message for length calculation.\n");
        free(bytestream);
        return;
    }

    // Ensure length is calculated correctly
    if (len <= 0) {
        printf("Invalid bytestream length: %d\n", len);
        releaseMsg(temp);
        free(bytestream);
        return;
    }

    // Debug output
    printf("��������%s:%d��DNS����\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

    // ���û��˷���DNS��Ӧ����
    int ret = sendto(sock, (char*)bytestream, len, 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
    if (ret == SOCKET_ERROR) {
        int error = WSAGetLastError();
        printf("sendto failed with error: %d\n", error);
    }
    else {
        if (cmdOption == 1) {
            bytestreamInfo(bytestream); // ��ӡbytestream��Ϣ
            debug(msg); // ��ӡDNS������Ϣ
        }
        printf("���û��˷���DNS��Ӧ���ĳɹ�\n");
    }

    // Cleanup
    releaseMsg(temp);
    free(bytestream);
}



// ת��DNS��Ӧ���ĸ��û���
void forward_dns_response(int sock, unsigned char* buf, int len, struct sockaddr_in clientAddr)
{
    int addrLen = sizeof(clientAddr);

    //����
    printf("��������%s:%d��DNS����\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
    //

    // ���û��˷���DNS��Ӧ����
    int ret = sendto(sock, (char*)buf, len, 0, (struct sockaddr*)&clientAddr, addrLen);
    if (ret == SOCKET_ERROR)
        printf("sendto failed with error: %d\n", WSAGetLastError());
    else
    {
        cmdOption == 1 ? bytestreamInfo(buf) : (void)0; // ��ӡbytestream��Ϣ
        printf("���û��˷���DNS��Ӧ���ĳɹ�\n");
    }
}