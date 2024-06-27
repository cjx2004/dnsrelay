#include "dns_relay_server.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_DNS_PACKET_SIZE 1024 // DNS请求报文最大长度
#define MAX_LINE_LENGTH 512  //txt行数

extern int cmdOption;

unsigned char currentdomain[MAX_DOMAIN_LENGTH];
unsigned short currentid;

// 通过线程池并发处理DNS请求
void handle_dns_request(struct Trie* trie, struct Cache* cache, SOCKET sock, struct sockaddr_in clientAddr, const char* remoteDnsAddr)
{
    unsigned short offset = 0;
    unsigned char buf[MAX_DNS_PACKET_SIZE]; // 收到的DNS请求字节流

    while (1)
    {
        // 接收来自用户端的DNS请求字节流
        int clientAddrLen = sizeof(clientAddr);
        //超时处理
        int len = recvfrom(sock, (char*)buf, MAX_DNS_PACKET_SIZE, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (len == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAETIMEDOUT) {
                // 处理超时情况，可以重新发送请求或者返回失败响应
                printf("请求超时，正在重新发送请求...\n");
                resendRequest();

            }
            else {
                // 处理其他错误情况
                printf("发生其他错误：%d\n", WSAGetLastError());
            }
        }

        //测试
        printf("recev from %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        //

        Dns_Msg* msg = NULL;
        offset = 0;
        msg = bytestream_to_dnsmsg(buf, &offset);

        cmdOption == 1 ? bytestreamInfo(buf) : (void)0; // 打印DNS请求报文的字节流
        cmdOption == 1 ? debug(msg) : (void)0;     // 打印DNS请求报文的结构体

        if (msg->header->qr == 0 && msg->header->opcode == 0) // 只处理DNS请求报文，opcode 0：标准查询
        {
            unsigned char domain[MAX_DOMAIN_LENGTH];
            transDN(msg->question->qname, domain); // 取出域名
            printf("收到来自用户端的DNS请求,域名为%s\n", domain);

            unsigned char* ipAddress = findIpAddress(trie, cache, domain); // 查找域名对应的IP地址

            if (ipAddress != NULL && ((ipAddress[4] == '\0' && msg->question->qtype == TYPE_A) || (ipAddress[4] != '\0' && msg->question->qtype == TYPE_AAAA)))                                         // 如果找到了,则发送DNS响应报文
            {
                printf("中继服务器查找成功,域名为%s,IP地址为%d.%d.%d.%d\n", domain, ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
                //拦截功能在这实现
                addAnswer(msg, ipAddress, 60, msg->question->qtype);    // 将IP地址添加到DNS响应报文中，更新ttl时间
                send_dns_response(sock, msg, clientAddr); // 发送DNS响应报文
            }
            else // 如果没找到,则转发DNS请求报文给远程DNS服务器
            {
                //printf("中继服务器查找失败,转发DNS请求报文给远程DNS服务器\n");

                // 将id和客户端绑定,产生新的id
                unsigned short newId = translate_id(msg->header->id, clientAddr);
                //新id是个映射的索引值
                buf[0] = newId >> 8;
                buf[1] = newId;

                //备用
                transDN(msg->question->qname, currentdomain); // 取出域名
                currentid = msg->header->id;

                forward_dns_request(sock, buf, len, remoteDnsAddr); // 转发DNS请求报文给远程DNS服务器
            }
        }
        else if (msg->header->qr == 1) // 处理从远程DNS服务器返回的DNS响应报文
        {
            printf("收到来自远程DNS服务器的DNS响应报文\n");
            unsigned char domain[MAX_DOMAIN_LENGTH];
            unsigned char ipAddr[16];
            unsigned int ttl;
            unsigned short type;
            getDN_IP(buf, domain, ipAddr, &ttl, &type);

            //更新文件
            int mark = 0;
            FILE* fp = fopen("dnsrelay.txt", "r+");  // 使用 "r+" 模式以读写方式打开文件
            if (fp == NULL) {
                // 打开失败
                printf("Failed to open dnsrelay.txt\n");
                return;
            }

            // 读取文件中的每一行
            char line[MAX_LINE_LENGTH];
            long last_pos = 0;  // 记录最后一行的文件位置
            while (fgets(line, MAX_LINE_LENGTH, fp)) {
                // 域名和4个字节的IP地址
                char txtdomain[MAX_LINE_LENGTH];
                unsigned char ip[4] = { 0, 0, 0, 0 };
                // 通过 sscanf 解析每一行, domain 和 ip 应分别读取域名和4个IP地址字段
                if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], txtdomain) != 5) {
                    // 如果解析失败
                    printf("Invalid line in dnsrelay.txt\n");
                    continue;
                }
                else {
                    if (strcmp(txtdomain, domain) == 0) {
                        mark = 1;
                        break;
                    }
                }
                last_pos = ftell(fp);  // 记录每一行的结束位置
            }

            if (!mark) {
                // 如果没有找到匹配的域名，则添加新的条目
                fseek(fp, last_pos, SEEK_SET);  // 定位到文件的末尾
                fprintf(fp, "%d.%d.%d.%d %s\n", ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3], domain);
            }

            // 关闭文件
            fclose(fp);

            const struct sockaddr_in clientAddr = retrieve_clientAddr(msg->header->id); // 通过id找到客户端地址，这里是通过索引在键值对数组里面找
            unsigned short preId = retrieve_id(msg->header->id);                    // 通过新id（索引）找到原始id
            if (currentid == preId) {
                addEntry(cache, domain, ipAddr, type, ttl);
            }
            buf[0] = preId >> 8;
            buf[1] = preId;

            forward_dns_response(sock, buf, len, clientAddr); // 转发DNS响应报文给用户端
        }
        else // 直接转发DNS报文给远程DNS服务器,多查询功能
        {
            unsigned short newId = translate_id(msg->header->id, clientAddr);
            buf[0] = newId >> 8;
            buf[1] = newId;

            forward_dns_request(sock, buf, len, remoteDnsAddr); // 转发DNS请求报文给远程DNS服务器
        }

        removeExpiredEntries(cache); // 每次处理完一个DNS请求,删除过期的缓存记录
        releaseMsg(msg);             // 释放DNS报文
    }
}


// 查找域名对应的IP地址
unsigned char* findIpAddress(struct Trie* trie, struct Cache* cache, unsigned char domain[MAX_DOMAIN_LENGTH])
{
    unsigned char ipAddr[16];
    unsigned char* ipAddress = NULL;

    // 先在缓存表中查找,找到返回
    // 尝试在缓存表中查找IPv4地址
    if (findEntry(cache, domain, ipAddr, 1))
    {
        // 如果找到IPv4地址，打印找到的信息
        printf("在缓存表查找成功,域名为%s,IPv4地址为%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);

        // 为IP地址分配内存，大小为4字节
        ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 4);

        // 将找到的IP地址复制到分配的内存中
        memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 4);

        // 添加一个终止符以确保字符串结尾（虽然对于IP地址来说这不是必需的，但以防万一）
        ipAddress[4] = '\0';
    }
    // 尝试在缓存表中查找IPv6地址
    else if (findEntry(cache, domain, ipAddr, 28))
    {
        // 如果找到IPv6地址，打印找到的信息
        printf("在缓存表查找成功,域名为%s,IPv6地址为%d.%d.%d.%d.%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3], ipAddr[4], ipAddr[5], ipAddr[6], ipAddr[7]);

        // 为IP地址分配内存，大小为16字节
        ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 16);

        // 将找到的IP地址复制到分配的内存中
        memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 16);
    }
    else
    {
        // 如果在本地表中找到了记录,将其添加到缓存表中
        int node = findNode(trie, domain);
        // 检查节点是否有效，即是否在字典树中找到匹配的域名
        if (node != 0)
        {
            // 将字典树中找到的IP地址复制到ipAddr数组中
            memcpy(ipAddr, trie->toIp[node], sizeof(ipAddr));
            // 将找到的域名和IP地址添加到缓存表中，并设置缓存的生存时间（TTL）
            addEntry(cache, domain, ipAddr, 1, CACHE_TTL);
            // 打印找到的IP地址信息
            printf("在本地字典树查找成功,域名为%s,IP地址为%d.%d.%d.%d\n", domain, ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);
            // 为IP地址分配内存，大小为5字节
            ipAddress = (unsigned char*)malloc(sizeof(unsigned char) * 5);
            // 将找到的IP地址复制到新分配的内存中
            memcpy(ipAddress, ipAddr, sizeof(unsigned char) * 5);
            // 添加一个终止符以确保字符串结尾
            ipAddress[4] = '\0';
        }
        else // 本地表和缓存表都没有找到,需要转发到远程DNS服务器
        {
            int mark = 0;
            // 打开dnsrelay.txt文件
            FILE* fp = fopen("dnsrelay.txt", "r");
            if (fp == NULL)
            {
                // 如果打开失败,打印错误信息并返回
                printf("Failed to open dnsrelay.txt\n");
                return;
            }

            // 读取文件中的每一行
            char line[MAX_LINE_LENGTH];
            while (fgets(line, MAX_LINE_LENGTH, fp))
            {
                // 域名和4个字节的IP地址
                char txtdomain[MAX_LINE_LENGTH];
                unsigned char ip[4] = { 0, 0, 0, 0 };
                // 通过sscanf解析每一行,domain和ip应分别读取域名和4个IP地址字段
                if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], txtdomain) != 5)
                {
                    // 如果解析失败,打印错误信息并跳过这一行
                    printf("Invalid line in dnsrelay.txt: %s\n", line);
                    continue;
                }
                else {
                    if (strcmp(txtdomain, domain) == 0) {
                        printf("中继服务器查找成功,域名为%s,IP地址为%d.%d.%d.%d\n", txtdomain, ip[0], ip[1], ip[2], ip[3]);
                        mark = 1;
                        break;
                    }

                }                
            }
            // 关闭文件
            fclose(fp);
            if (mark == 0) {
                printf("本地表和缓存表都未查找到域名%s,需要访问远程DNS服务器\n", domain);
            }
            return NULL;
        }
    }
    return ipAddress;
}

// 转发DNS请求报文给远程DNS服务器
void forward_dns_request(int sock, unsigned char* buf, int len, const char* remoteDnsAddr)
{
    // 初始化远程地址结构体
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_addr.s_addr = inet_addr(remoteDnsAddr); // 设定远程DNS服务器地址
    remoteAddr.sin_port = htons(53);                       // 设定DNS服务器端口号为53

    // 向远程DNS服务器发送DNS请求报文
    int ret = sendto(sock, (char*)buf, len, 0, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
    if (ret == SOCKET_ERROR)
        printf("sendto failed with error: %d\n", WSAGetLastError());
    else
    {
        // 在调试模式下打印bytestream信息
        if (cmdOption == 1) bytestreamInfo(buf);
        printf("向远程DNS服务器发送DNS请求报文成功\n");
    }
}



// 向用户端发送DNS响应报文
void send_dns_response(int sock, Dns_Msg* msg, struct sockaddr_in clientAddr)
{
    unsigned char* bytestream = dnsmsg_to_bytestream(msg);
    // 检查转换是否成功
    if (bytestream == NULL) {
        printf("Failed to convert DNS message to bytestream.\n");
        return;
    }

    int len = 0;
    // 将bytestream转换回DNS消息以计算长度
    Dns_Msg* temp = bytestream_to_dnsmsg(bytestream, (unsigned short*)(&len));
    // 检查报文转换是否成功
    if (temp == NULL) {
        printf("Failed to parse bytestream back to DNS message for length calculation.\n");
        free(bytestream);
        return;
    }

    // 确保长度计算正确
    if (len <= 0) {
        printf("Invalid bytestream length: %d\n", len);
        releaseMsg(temp);
        free(bytestream);
        return;
    }

    printf("接收来自%s:%d的DNS请求\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

    // 向用户端发送DNS响应报文
    int ret = sendto(sock, (char*)bytestream, len, 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
    // 检查发送是否成功
    if (ret == SOCKET_ERROR) {
        printf("sendto failed with error: %d\n", WSAGetLastError());
    }
    else {
        // 如果是调试模式，打印bytestream和DNS报文信息
        if (cmdOption == 1) {
            bytestreamInfo(bytestream);
            debug(msg);
        }
        printf("向用户端发送DNS响应报文成功\n");
    }

    // 读取文件中的每一行
    /*char line[MAX_LINE_LENGTH];
    while (fgets(line, MAX_LINE_LENGTH, fp))
    {
        // 域名和4个字节的IP地址
        char txtdomain[MAX_LINE_LENGTH];
        unsigned char ip[4] = { 0, 0, 0, 0 };
        // 通过sscanf解析每一行,domain和ip应分别读取域名和4个IP地址字段
        if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], txtdomain) != 5)
        {
            // 如果解析失败,打印错误信息并跳过这一行
            printf("Invalid line in dnsrelay.txt: %s\n", line);
            continue;
        }
        else {
            if (strcmp(txtdomain, domain) == 0) {
                printf("中继服务器查找成功,域名为%s,IP地址为%d.%d.%d.%d\n", txtdomain, ip[0], ip[1], ip[2], ip[3]);
                mark = 1;
                break;
            }

        }
    }
    // 关闭文件
    fclose(fp);

    if (mark == 0) {
        printf("本地表和缓存表都未查找到域名%s,需要访问远程DNS服务器\n", domain);
    }
    */
    // Cleanup
    releaseMsg(temp);
    free(bytestream);
}



// 转发DNS响应报文给用户端
void forward_dns_response(int sock, unsigned char* buf, int len, struct sockaddr_in clientAddr)
{
    int addrLen = sizeof(clientAddr);

    //测试
    printf("接收来自%s:%d的DNS请求\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
    //
  
    // 读取文件中的每一行
    /*char line[MAX_LINE_LENGTH];
    while (fgets(line, MAX_LINE_LENGTH, fp))
    {
        // 域名和4个字节的IP地址
        char txtdomain[MAX_LINE_LENGTH];
        unsigned char ip[4] = { 0, 0, 0, 0 };
        // 通过sscanf解析每一行,domain和ip应分别读取域名和4个IP地址字段
        if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], txtdomain) != 5)
        {
            // 如果解析失败,打印错误信息并跳过这一行
            printf("Invalid line in dnsrelay.txt: %s\n", line);
            continue;
        }
        else {
            if (strcmp(txtdomain, domain) == 0) {
                printf("中继服务器查找成功,域名为%s,IP地址为%d.%d.%d.%d\n", txtdomain, ip[0], ip[1], ip[2], ip[3]);
                mark = 1;
                break;
            }

        }
    }
    // 关闭文件
    fclose(fp);
   
    if (mark == 0) {
        printf("本地表和缓存表都未查找到域名%s,需要访问远程DNS服务器\n", domain);
    }
    */
    // 向用户端发送DNS响应报文
    int ret = sendto(sock, (char*)buf, len, 0, (struct sockaddr*)&clientAddr, addrLen);
    if (ret == SOCKET_ERROR)
        printf("sendto failed with error: %d\n", WSAGetLastError());
    else
    {
        cmdOption == 1 ? bytestreamInfo(buf) : (void)0; // 打印bytestream信息
        printf("向用户端发送DNS响应报文成功\n");
    }
}

//超时处理
void resendRequest() {
    // 重新建立连接
    printf("正在重新建立连接...\n");
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        printf("创建监听socket失败.\n");
        return 1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;//默认ipv4
    serverAddr.sin_port = htons(53);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);//IP 地址，使用 htonl 函数将主机字节序转换为网络字节序。INADDR_ANY 表示绑定到所有可用的网络接口。

    // 将目标设备的IP地址转换为二进制形式，并赋值给serverAddr.sin_addr

    if (bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        printf("绑定监听socket到端口%d失败.\n", 53);
        closesocket(sock);
        return 1;
    }
}