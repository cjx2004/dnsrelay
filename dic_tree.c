#include "dic_tree.h"

#define MAX_LINE_LENGTH 512

/*
1、插入域名和 IP 地址 (insertDomainNode):
时间复杂度：O(n)，其中 n 是域名的长度。需要遍历整个域名字符串，对于每个字符，执行相应的插入操作。
2、查找域名对应的 IP 地址 (searchDomainNode):
时间复杂度：O(n)，其中 n 是域名的长度。同样需要遍历整个域名字符串，以确定 Trie 树中是否存在该域名。
3、删除域名和对应的 IP 地址 (eraseDomainNode):
时间复杂度：O(n)，在最坏情况下，可能需要遍历域名的全部字符来定位节点，然后从 Trie 树中删除与该域名相关的所有节点。实际复杂度可能更高，因为删除操作可能需要回溯到根节点以删除不再需要的内部节点。
4、加载本地 DNS 表 (loadLocalTableEntries):
时间复杂度：O(k * n)，其中 k 是文件中域名的数量，n 是平均域名长度。这个函数读取文件中的每一行，并对每一行调用 insertDomainNode 函数。
5、简化域名 (convertToLowerCase):
时间复杂度：O(m)，其中 m 是域名的长度。这个函数将域名中的每个字符转换为小写，如果域名中的字符是字母的话。
*/


// 初始化Trie树
void initializeTrie(struct Trie* trie)
{
    // 将trie树所有节点的值清零
    memset(trie->tree, 0, sizeof(trie->tree));
    // 将前缀数组清零
    memset(trie->prefix, 0, sizeof(trie->prefix));
    // 将结束标志数组清零
    memset(trie->isEnd, false, sizeof(trie->isEnd));
    // 将IP地址数组清零
    memset(trie->toIp, 0, sizeof(trie->toIp));
    // 设置树的大小为0 
    trie->size = 0;
}

void loadLocalTableEntriesEntries(struct Trie* trie)
{
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
        char domain[MAX_LINE_LENGTH];
        unsigned char ip[4] = { 0, 0, 0, 0 };
        // 通过sscanf解析每一行,domain和ip应分别读取域名和4个IP地址字段
        if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], domain) != 5)
        {
            // 如果解析失败,打印错误信息并跳过这一行
            printf("Invalid line in dnsrelay.txt: %s\n", line);
            continue;
        }
        // 将域名和IP地址插入Trie树中
        insertDomainNode(trie, domain, ip);
    }

    // 关闭文件
    fclose(fp);
}

/*
root 变量在遍历域名的过程中，从根节点出发，逐步更新为当前字符对应的节点位置。
root 初始值为 0，表示根节点。随着遍历的进行，root 更新为当前字符对应的子节点位置，直到遍历完所有字符。
最终，root 指向域名的最后一个字符对应的节点，并在此节点保存 IP 地址和标记为结束节点。
*/

// 在Trie树中插入一个域名和对应的IP地址
void insertDomainNode(struct Trie* trie, const char domain[], unsigned char ipAddr[4])
{
    // 获取域名的长度
    int len = strlen(domain);
    if (len == 0)
        return;

    // 申请内存保存域名的副本
    char* temp = (char*)malloc(sizeof(char) * (len + 1));
    strcpy(temp, domain);

    // 简化域名，将大写字母转换为小写字母
    for (int i = 0; i < len; i++)
    {
        if (temp[i] >= 'A' && temp[i] <= 'Z')
            temp[i] = temp[i] - 'A' + 'a';
    }

    // 初始化根节点为0
    int root = 0;

    // 遍历域名的每个字符
    for (int i = 0; i < len; i++)
    {
        // 计算当前字符的 id
        int id;
        if (temp[i] >= 'a' && temp[i] <= 'z')
            id = temp[i] - 'a';
        else if (temp[i] >= '0' && temp[i] <= '9')
            id = temp[i] - '0' + 26;  // 数字部分从26开始计数
        else if (temp[i] == '-')
            id = 36;
        else if (temp[i] == '.')
            id = 37;
        else
        {
            // 如果域名包含非法字符，进行适当的处理
            printf("Invalid characters in domain\n");
            free(temp);
            return;
        }

        // 如果不存在对应id的子节点，则创建一个新的节点
        if (!trie->tree[root][id])
            trie->tree[root][id] = ++trie->size;

        // 记录前缀
        trie->prefix[trie->tree[root][id]] = root;
        // 移动到下一个节点
        root = trie->tree[root][id];
    }

    // 将当前节点标记为结束节点
    trie->isEnd[root] = true;
    // 复制IP地址
    memcpy(trie->toIp[root], ipAddr, sizeof(unsigned char) * 4);
    // 释放临时内存
    free(temp);
}

// 查找一个域名在Trie树中对应的IP地址，返回节点值，根据toIp找IP地址
int searchDomainNode(struct Trie* trie, const char domain[])
{
    // 获取域名的长度
    int len = strlen(domain);
    if (len == 0)
        return 0;

    // 申请内存保存域名的副本
    char* temp = (char*)malloc(sizeof(char) * (len + 1));
    strcpy(temp, domain);

    // 简化域名，将大写字母转换为小写字母
    for (int i = 0; i < len; i++)
    {
        if (temp[i] >= 'A' && temp[i] <= 'Z')
            temp[i] = temp[i] - 'A' + 'a';
    }

    // 初始化根节点为0
    int root = 0;

    // 遍历域名的每个字符
    for (int i = 0; i < len; i++)
    {
        int id;
        if (temp[i] >= 'a' && temp[i] <= 'z')
            id = temp[i] - 'a';
        else if (temp[i] >= '0' && temp[i] <= '9')
            id = temp[i] - '0' + 26;  // 数字部分从26开始计数
        else if (temp[i] == '-')
            id = 36;
        else if (temp[i] == '.')
            id = 37;
        else
        {
            // 如果域名包含非法字符，进行适当的处理
            printf("Invalid characters in domain\n");
            free(temp);
            return;
        }

        // 如果不存在对应id的子节点，则返回0
        if (!trie->tree[root][id])
        {
            free(temp);
            return 0;
        }

        // 移动到下一个节点
        root = trie->tree[root][id];
    }

    // 如果找到的节点不是终止节点，说明域名不在Trie树中，返回0
    if (!trie->isEnd[root])
    {
        free(temp);
        return 0;
    }

    // 释放临时内存
    free(temp);
    // 返回找到的节点
    return root;
}

// 在Trie树中删除一个域名和对应的IP地址
void eraseDomainNode(struct Trie* trie, const char domain[])
{
    // 检查是否为空串
    int len = strlen(domain);
    if (len == 0)
    {
        printf("Length of string is 0, error handling!\n");
        return;
    }

    // 查找这个域名是否存在
    int root = searchDomainNode(trie, domain);
    if (root == 0)
    {
        printf("Domain does not exist in local tree, error handling!\n");
        return;
    }

    // 将这个节点标记为非终止节点
    trie->isEnd[root] = false;

    // 复制一份域名，用于后面的操作
    char* temp = (char*)malloc(sizeof(char) * (len + 1));
    strcpy(temp, domain);

    // 简化域名，将大写字母转换为小写字母
    for (int i = 0; i < len; i++)
    {
        if (temp[i] >= 'A' && temp[i] <= 'Z')
            temp[i] = temp[i] - 'A' + 'a';
    }

    // 如果这个节点不是根节点
    while (root != 0)
    {
        int id;
        if (temp[len - 1] >= 'a' && temp[len - 1] <= 'z')
            id = temp[len - 1] - 'a';      // 小写字母部分从0开始计数
        else if (temp[len - 1] >= '0' && temp[len - 1] <= '9')
            id = temp[len - 1] - '0' + 26; // 数字部分从26开始计数
        else if (temp[len - 1] == '-')
            id = 36;                       // '-' 对应的id
        else if (temp[len - 1] == '.')
            id = 37;                       // '.' 对应的id
        else
        {
            // 如果域名包含非法字符，进行适当的处理
            printf("Invalid characters in domain\n");
            free(temp);
            return;
        }

        // 如果这个节点的所有子节点都被删除了，就删除这个节点
        bool haveChild = false;
        for (int i = 0; i < MAX_ALPHABET; i++)
        {
            // 如果这个节点的第i个子节点存在，就说明这个节点还有子节点
            if (trie->tree[root][i])
            {
                haveChild = true;
                break;
            }
        }
        if (haveChild)
            break;

        // 删除当前节点及其父节点的关系
        int preNode = trie->prefix[root];
        trie->tree[preNode][id] = 0;
        trie->prefix[root] = 0;
        root = preNode;
        len--;
    }

    // 释放临时内存
    free(temp);
}

// 简化域名，将大写字母转换为小写字母
void convertToLowerCase(char* domain)
{
    int len = strlen(domain);
    for (int i = 0; i < len; i++)
    {
        if (domain[i] >= 'A' && domain[i] <= 'Z')
            domain[i] = domain[i] - 'A' + 'a';
    }
}
