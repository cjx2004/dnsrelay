#include "dns_relay_server.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_DNS_PACKET_SIZE 1024 // DNS��������󳤶�
#define MAX_LINE_LENGTH 512  //txt����

extern int cmdOption;

unsigned char currentdomain[MAX_DOMAIN_LENGTH];
unsigned short currentid;

// ͨ���̳߳ز�������DNS����
void handle_dns_request(struct Trie* trie, struct Cache* cache, SOCKET sock, struct sockaddr_in clientAddr, const char* remoteDnsAddr)
{
    unsigned short offset = 0;
    unsigned char buf[MAX_DNS_PACKET_SIZE]; // �յ���DNS�����ֽ���

    while (1)
    {
        // ���������û��˵�DNS�����ֽ���
        int clientAddrLen = sizeof(clientAddr);
        //��ʱ����
        int len = recvfrom(sock, (char*)buf, MAX_DNS_PACKET_SIZE, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (len == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAETIMEDOUT) {
                // ����ʱ������������·���������߷���ʧ����Ӧ
                printf("����ʱ���������·�������...\n");
                resendRequest();

            }
            else {
                // ���������������
                printf("������������%d\n", WSAGetLastError());
            }
        }

        //����
        printf("recev from %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        //

        Dns_Msg* msg = NULL;
        offset = 0;
        msg = bytestream_to_dnsmsg(buf, &offset);

        cmdOption == 1 ? bytestreamInfo(buf) : (void)0; // ��ӡDNS�����ĵ��ֽ���
        cmdOption == 1 ? debug(msg) : (void)0;     // ��ӡDNS�����ĵĽṹ��

        if (msg->header->qr == 0 && msg->header->opcode == 0) // ֻ����DNS�����ģ�opcode 0����׼��ѯ
        {
            unsigned char domain[MAX_DOMAIN_LENGTH];
            transDN(msg->question->qname, domain); // ȡ������
            printf("�յ������û��˵�DNS����,����Ϊ%s\n", domain);

            unsigned char* ipAddress = findIpAddress(trie, cache, domain); // ����������Ӧ��IP��ַ

            if (ipAddress != NULL && ((ipAddress[4] == '\0' && msg->question->qtype == TYPE_A) || (ipAddress[4] != '\0' && msg->question->qtype == TYPE_AAAA)))                                         // ����ҵ���,����DNS��Ӧ����
            {
                printf("�м̷��������ҳɹ�,����Ϊ%s,IP��ַΪ%d.%d.%d.%d\n", domain, ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
                //���ع�������ʵ��
                addAnswer(msg, ipAddress, 60, msg->question->qtype);    // ��IP��ַ��ӵ�DNS��Ӧ�����У�����ttlʱ��
                send_dns_response(sock, msg, clientAddr); // ����DNS��Ӧ����
            }
            else // ���û�ҵ�,��ת��DNS�����ĸ�Զ��DNS������
            {
                //printf("�м̷���������ʧ��,ת��DNS�����ĸ�Զ��DNS������\n");

                // ��id�Ϳͻ��˰�,�����µ�id
                unsigned short newId = translate_id(msg->header->id, clientAddr);
                //��id�Ǹ�ӳ�������ֵ
                buf[0] = newId >> 8;
                buf[1] = newId;

                //����
                transDN(msg->question->qname, currentdomain); // ȡ������
                currentid = msg->header->id;

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

            //�����ļ�
            int mark = 0;
            FILE* fp = fopen("dnsrelay.txt", "r+");  // ʹ�� "r+" ģʽ�Զ�д��ʽ���ļ�
            if (fp == NULL) {
                // ��ʧ��
                printf("Failed to open dnsrelay.txt\n");
                return;
            }

            // ��ȡ�ļ��е�ÿһ��
            char line[MAX_LINE_LENGTH];
            long last_pos = 0;  // ��¼���һ�е��ļ�λ��
            while (fgets(line, MAX_LINE_LENGTH, fp)) {
                // ������4���ֽڵ�IP��ַ
                char txtdomain[MAX_LINE_LENGTH];
                unsigned char ip[4] = { 0, 0, 0, 0 };
                // ͨ�� sscanf ����ÿһ��, domain �� ip Ӧ�ֱ��ȡ������4��IP��ַ�ֶ�
                if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], txtdomain) != 5) {
                    // �������ʧ��
                    printf("Invalid line in dnsrelay.txt\n");
                    continue;
                }
                else {
                    if (strcmp(txtdomain, domain) == 0) {
                        mark = 1;
                        break;
                    }
                }
                last_pos = ftell(fp);  // ��¼ÿһ�еĽ���λ��
            }

            if (!mark) {
                // ���û���ҵ�ƥ���������������µ���Ŀ
                fseek(fp, last_pos, SEEK_SET);  // ��λ���ļ���ĩβ
                fprintf(fp, "%d.%d.%d.%d %s\n", ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3], domain);
            }

            // �ر��ļ�
            fclose(fp);

            const struct sockaddr_in clientAddr = retrieve_clientAddr(msg->header->id); // ͨ��id�ҵ��ͻ��˵�ַ��������ͨ�������ڼ�ֵ������������
            unsigned short preId = retrieve_id(msg->header->id);                    // ͨ����id���������ҵ�ԭʼid
            if (currentid == preId) {
                addEntry(cache, domain, ipAddr, type, ttl);
            }
            buf[0] = preId >> 8;
            buf[1] = preId;

            forward_dns_response(sock, buf, len, clientAddr); // ת��DNS��Ӧ���ĸ��û���
        }
        else // ֱ��ת��DNS���ĸ�Զ��DNS������,���ѯ����
        {
            unsigned short newId = translate_id(msg->header->id, clientAddr);
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
    // �����ڻ�����в���IPv4��ַ
    if (findEntry(cache, domain, ipAddr, 1))
    {
        // ����ҵ�IPv4��ַ����ӡ�ҵ�����Ϣ
        printf("�ڻ������ҳɹ�,����Ϊ%s,IPv4��ַΪ%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);

        // ΪIP��ַ�����ڴ棬��СΪ4�ֽ�
        ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 4);

        // ���ҵ���IP��ַ���Ƶ�������ڴ���
        memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 4);

        // ���һ����ֹ����ȷ���ַ�����β����Ȼ����IP��ַ��˵�ⲻ�Ǳ���ģ����Է���һ��
        ipAddress[4] = '\0';
    }
    // �����ڻ�����в���IPv6��ַ
    else if (findEntry(cache, domain, ipAddr, 28))
    {
        // ����ҵ�IPv6��ַ����ӡ�ҵ�����Ϣ
        printf("�ڻ������ҳɹ�,����Ϊ%s,IPv6��ַΪ%d.%d.%d.%d.%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3], ipAddr[4], ipAddr[5], ipAddr[6], ipAddr[7]);

        // ΪIP��ַ�����ڴ棬��СΪ16�ֽ�
        ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 16);

        // ���ҵ���IP��ַ���Ƶ�������ڴ���
        memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 16);
    }
    else
    {
        // ����ڱ��ر����ҵ��˼�¼,������ӵ��������
        int node = findNode(trie, domain);
        // ���ڵ��Ƿ���Ч�����Ƿ����ֵ������ҵ�ƥ�������
        if (node != 0)
        {
            // ���ֵ������ҵ���IP��ַ���Ƶ�ipAddr������
            memcpy(ipAddr, trie->toIp[node], sizeof(ipAddr));
            // ���ҵ���������IP��ַ��ӵ�������У������û��������ʱ�䣨TTL��
            addEntry(cache, domain, ipAddr, 1, CACHE_TTL);
            // ��ӡ�ҵ���IP��ַ��Ϣ
            printf("�ڱ����ֵ������ҳɹ�,����Ϊ%s,IP��ַΪ%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);
            // ΪIP��ַ�����ڴ棬��СΪ5�ֽ�
            ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 5);
            // ���ҵ���IP��ַ���Ƶ��·�����ڴ���
            memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 5);
            // ���һ����ֹ����ȷ���ַ�����β
            ipAddress[4] = '\0';
        }
        else // ���ر�ͻ����û���ҵ�,��Ҫת����Զ��DNS������
        {
            int mark = 0;
            // ��dnsrelay.txt�ļ�
            FILE* fp = fopen("dnsrelay.txt", "r");
            if (fp == NULL)
            {
                // �����ʧ��,��ӡ������Ϣ������
                printf("Failed to open dnsrelay.txt\n");
                return;
            }

            // ��ȡ�ļ��е�ÿһ��
            char line[MAX_LINE_LENGTH];
            while (fgets(line, MAX_LINE_LENGTH, fp))
            {
                // ������4���ֽڵ�IP��ַ
                char txtdomain[MAX_LINE_LENGTH];
                unsigned char ip[4] = { 0, 0, 0, 0 };
                // ͨ��sscanf����ÿһ��,domain��ipӦ�ֱ��ȡ������4��IP��ַ�ֶ�
                if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], txtdomain) != 5)
                {
                    // �������ʧ��,��ӡ������Ϣ��������һ��
                    printf("Invalid line in dnsrelay.txt: %s\n", line);
                    continue;
                }
                else {
                    if (strcmp(txtdomain, domain) == 0) {
                        printf("�м̷��������ҳɹ�,����Ϊ%s,IP��ַΪ%d.%d.%d.%d\n", txtdomain, ip[0], ip[1], ip[2], ip[3]);
                        mark = 1;
                        break;
                    }

                }                
            }
            // �ر��ļ�
            fclose(fp);
            if (mark == 0) {
                printf("���ر�ͻ����δ���ҵ�����%s,��Ҫ����Զ��DNS������\n", domain);
            }
            return NULL;
        }
    }
    return ipAddress;
}

// ת��DNS�����ĸ�Զ��DNS������
void forward_dns_request(int sock, unsigned char* buf, int len, const char* remoteDnsAddr)
{
    // ��ʼ��Զ�̵�ַ�ṹ��
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_addr.s_addr = inet_addr(remoteDnsAddr); // �趨Զ��DNS��������ַ
    remoteAddr.sin_port = htons(53);                       // �趨DNS�������˿ں�Ϊ53

    // ��Զ��DNS����������DNS������
    int ret = sendto(sock, (char*)buf, len, 0, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
    if (ret == SOCKET_ERROR)
        printf("sendto failed with error: %d\n", WSAGetLastError());
    else
    {
        // �ڵ���ģʽ�´�ӡbytestream��Ϣ
        if (cmdOption == 1) bytestreamInfo(buf);
        printf("��Զ��DNS����������DNS�����ĳɹ�\n");
    }
}



// ���û��˷���DNS��Ӧ����
void send_dns_response(int sock, Dns_Msg* msg, struct sockaddr_in clientAddr)
{
    unsigned char* bytestream = dnsmsg_to_bytestream(msg);
    // ���ת���Ƿ�ɹ�
    if (bytestream == NULL) {
        printf("Failed to convert DNS message to bytestream.\n");
        return;
    }

    int len = 0;
    // ��bytestreamת����DNS��Ϣ�Լ��㳤��
    Dns_Msg* temp = bytestream_to_dnsmsg(bytestream, (unsigned short*)(&len));
    // ��鱨��ת���Ƿ�ɹ�
    if (temp == NULL) {
        printf("Failed to parse bytestream back to DNS message for length calculation.\n");
        free(bytestream);
        return;
    }

    // ȷ�����ȼ�����ȷ
    if (len <= 0) {
        printf("Invalid bytestream length: %d\n", len);
        releaseMsg(temp);
        free(bytestream);
        return;
    }

    printf("��������%s:%d��DNS����\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

    // ���û��˷���DNS��Ӧ����
    int ret = sendto(sock, (char*)bytestream, len, 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
    // ��鷢���Ƿ�ɹ�
    if (ret == SOCKET_ERROR) {
        printf("sendto failed with error: %d\n", WSAGetLastError());
    }
    else {
        // ����ǵ���ģʽ����ӡbytestream��DNS������Ϣ
        if (cmdOption == 1) {
            bytestreamInfo(bytestream);
            debug(msg);
        }
        printf("���û��˷���DNS��Ӧ���ĳɹ�\n");
    }

    // ��ȡ�ļ��е�ÿһ��
    /*char line[MAX_LINE_LENGTH];
    while (fgets(line, MAX_LINE_LENGTH, fp))
    {
        // ������4���ֽڵ�IP��ַ
        char txtdomain[MAX_LINE_LENGTH];
        unsigned char ip[4] = { 0, 0, 0, 0 };
        // ͨ��sscanf����ÿһ��,domain��ipӦ�ֱ��ȡ������4��IP��ַ�ֶ�
        if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], txtdomain) != 5)
        {
            // �������ʧ��,��ӡ������Ϣ��������һ��
            printf("Invalid line in dnsrelay.txt: %s\n", line);
            continue;
        }
        else {
            if (strcmp(txtdomain, domain) == 0) {
                printf("�м̷��������ҳɹ�,����Ϊ%s,IP��ַΪ%d.%d.%d.%d\n", txtdomain, ip[0], ip[1], ip[2], ip[3]);
                mark = 1;
                break;
            }

        }
    }
    // �ر��ļ�
    fclose(fp);

    if (mark == 0) {
        printf("���ر�ͻ����δ���ҵ�����%s,��Ҫ����Զ��DNS������\n", domain);
    }
    */
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
  
    // ��ȡ�ļ��е�ÿһ��
    /*char line[MAX_LINE_LENGTH];
    while (fgets(line, MAX_LINE_LENGTH, fp))
    {
        // ������4���ֽڵ�IP��ַ
        char txtdomain[MAX_LINE_LENGTH];
        unsigned char ip[4] = { 0, 0, 0, 0 };
        // ͨ��sscanf����ÿһ��,domain��ipӦ�ֱ��ȡ������4��IP��ַ�ֶ�
        if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], txtdomain) != 5)
        {
            // �������ʧ��,��ӡ������Ϣ��������һ��
            printf("Invalid line in dnsrelay.txt: %s\n", line);
            continue;
        }
        else {
            if (strcmp(txtdomain, domain) == 0) {
                printf("�м̷��������ҳɹ�,����Ϊ%s,IP��ַΪ%d.%d.%d.%d\n", txtdomain, ip[0], ip[1], ip[2], ip[3]);
                mark = 1;
                break;
            }

        }
    }
    // �ر��ļ�
    fclose(fp);
   
    if (mark == 0) {
        printf("���ر�ͻ����δ���ҵ�����%s,��Ҫ����Զ��DNS������\n", domain);
    }
    */
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

//��ʱ����
void resendRequest() {
    // ���½�������
    printf("�������½�������...\n");
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        printf("��������socketʧ��.\n");
        return 1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;//Ĭ��ipv4
    serverAddr.sin_port = htons(53);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);//IP ��ַ��ʹ�� htonl �����������ֽ���ת��Ϊ�����ֽ���INADDR_ANY ��ʾ�󶨵����п��õ�����ӿڡ�

    // ��Ŀ���豸��IP��ַת��Ϊ��������ʽ������ֵ��serverAddr.sin_addr

    if (bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        printf("�󶨼���socket���˿�%dʧ��.\n", 53);
        closesocket(sock);
        return 1;
    }
}