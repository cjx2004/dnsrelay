#include "trie.h"

#define MAX_LINE_LENGTH 512

// ��ʼ��Trie��
void initTrie(struct Trie* trie)
{
    // ��trie�����нڵ��ֵ����
    memset(trie->tree, 0, sizeof(trie->tree));
    // ��ǰ׺��������
    memset(trie->prefix, 0, sizeof(trie->prefix));
    // ��������־��������
    memset(trie->isEnd, false, sizeof(trie->isEnd));
    // ��IP��ַ��������
    memset(trie->toIp, 0, sizeof(trie->toIp));
    // �������Ĵ�СΪ0 
    trie->size = 0;
}

void loadLocalTable(struct Trie* trie)
{
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
        char domain[MAX_LINE_LENGTH];
        unsigned char ip[4] = { 0, 0, 0, 0 };
        // ͨ��sscanf����ÿһ��,domain��ipӦ�ֱ��ȡ������4��IP��ַ�ֶ�
        if (sscanf(line, "%hhu.%hhu.%hhu.%hhu %s", &ip[0], &ip[1], &ip[2], &ip[3], domain) != 5)
        {
            // �������ʧ��,��ӡ������Ϣ��������һ��
            printf("Invalid line in dnsrelay.txt: %s\n", line);
            continue;
        }
        // ��������IP��ַ����Trie����
        insertNode(trie, domain, ip);
    }

    // �ر��ļ�
    fclose(fp);
}

// ��������,���������еĴ�д��ĸת����Сд��ĸ
void simplifyDomain(char domain[])
{
    // ��ȡ�����ĳ���
    int len = strlen(domain);
    int i;
    // ����������ÿ���ַ�
    for (i = 0; i < len; i++)
    {
        // �����ǰ�ַ�����.��-,����ת��ΪСд
        if (domain[i] != '.' && domain[i] != '-')
            domain[i] = tolower(domain[i]);
    }
    // ���������Ͻ�����
    domain[i] = '\0';
}

// ��Trie���в���һ�������Ͷ�Ӧ��IP��ַ
// eg:insertNode(trie, "www.baidu.com", "10.3.8.211")
void insertNode(struct Trie* trie, const char domain[], unsigned char ipAddr[4])
{
    // ��ȡ�����ĳ���
    int len = strlen(domain);
    if (len == 0)
        return;
    // �����ڴ汣�������ĸ���
    char* temp = (char*)malloc(sizeof(char) * (len + 1));
    // ��������
    strcpy(temp, domain);
    // ������,����д��ĸת��ΪСд��ĸ
    simplifyDomain(temp);
    // ��ʼ�����ڵ�Ϊ0
    int root = 0;
    // ����������ÿ���ַ�
    for (int i = 0; i < len; i++)
    {
        int id;
        // �����ǰ�ַ�������,idΪ�ַ���ֵ��ȥ'0'
        if (temp[i] >= '0' && temp[i] <= '9')
            id = temp[i] - '0';
        // �����ǰ�ַ���Сд��ĸ,idΪ�ַ���ֵ��ȥ'a'��10
        else if (temp[i] >= 'a' && temp[i] <= 'z')
            id = temp[i] - 'a' + 10;
        // �����ǰ�ַ���'-',idΪ36
        else if (temp[i] == '-')
            id = 36;
        // �����ǰ�ַ���'.',idΪ37
        else // temp[i] == '.'
            id = 37;

        // ��������ڶ�Ӧid���ӽڵ�,�򴴽�һ���µĽڵ�
        if (!trie->tree[root][id])
            trie->tree[root][id] = ++trie->size;

        // ��¼ǰ׺
        trie->prefix[trie->tree[root][id]] = root;
        // �ƶ�����һ���ڵ�
        root = trie->tree[root][id];
    }
    // ����ǰ�ڵ���Ϊ�����ڵ�
    trie->isEnd[root] = true;
    // ����IP��ַ
    memcpy(trie->toIp[root], ipAddr, sizeof(unsigned char) * 4);
    // �ͷ���ʱ�ڴ�
    free(temp);
}

// ����һ��������Trie���ж�Ӧ��IP��ַ
// eg:findNode(trie, "www.baidu.com")
int findNode(struct Trie* trie, const unsigned char domain[])
{
    // ��ȡ�����ĳ���
    int len = strlen((char*)domain);
    if (len == 0)
        return 0;
    // �����ڴ汣�������ĸ���
    char* temp = (char*)malloc(sizeof(char) * (len + 1));
    // ��������
    strcpy(temp, (char*)domain);
    // ������,����д��ĸת��ΪСд��ĸ
    simplifyDomain(temp);
    // ��ʼ�����ڵ�Ϊ0
    int root = 0;
    // ����������ÿ���ַ�
    for (int i = 0; i < len; i++)
    {
        // 'a'-'z'��Ӧ��idΪ10-35,'0'-'9'��Ӧ��idΪ0-9
        // �����'-',��Ӧ��idΪ36,�����'.',��Ӧ��idΪ37
        int id;
        if (temp[i] >= '0' && temp[i] <= '9')
            id = temp[i] - '0';
        else if (temp[i] >= 'a' && temp[i] <= 'z')
            id = temp[i] - 'a' + 10;
        else if (temp[i] == '-')
            id = 36;
        else // temp[i] == '.'
            id = 37;

        // ��������ڶ�Ӧid���ӽڵ�,�򷵻�0
        if (!trie->tree[root][id])
        {
            free(temp);
            return 0;
        }

        // �ƶ�����һ���ڵ�
        root = trie->tree[root][id];
    }
    // ����ҵ��Ľڵ㲻����ֹ�ڵ�,˵����������Trie����,����0
    if (trie->isEnd[root] == false)
    {
        free(temp);
        return 0;
    }
    // �ͷ���ʱ�ڴ�
    free(temp);
    // �����ҵ��Ľڵ�
    return root;
}

// ��Trie����ɾ��һ�������Ͷ�Ӧ��IP��ַ
// eg: deleteNode(trie, "www.baidu.com")
void deleteNode(struct Trie* trie, const unsigned char domain[])
{
    // ����Ƿ�Ϊ�մ�
    int len = strlen((char*)domain);
    if (len == 0)
        return;

    // ������������Ƿ����
    int root = findNode(trie, domain);
    if (root == 0)
        return;

    // ������ڵ���Ϊ����ֹ�ڵ�
    trie->isEnd[root] = false;

    // ����һ�����������ں���Ĳ���
    char* temp = (char*)malloc(sizeof(char) * (len + 1));
    strcpy(temp, (char*)domain);
    simplifyDomain(temp);

    // �������ڵ㲻�Ǹ��ڵ�
    while (root != 0)
    {
        int id;
        if (temp[len - 1] >= '0' && temp[len - 1] <= '9')
            id = temp[len - 1] - '0';
        else if (temp[len - 1] >= 'a' && temp[len - 1] <= 'z')
            id = temp[len - 1] - 'a' + 10;
        else if (temp[len - 1] == '-')
            id = 36;
        else // temp[len - 1] == '.'
            id = 37;

        // �������ڵ�������ӽڵ㶼��ɾ���ˣ���ɾ������ڵ�
        bool haveChild = false;
        for (int i = 0; i < MAX_ALPHABET; i++)
        {
            // �������ڵ�ĵ�i���ӽڵ���ڣ���˵������ڵ㻹���ӽڵ�
            if (trie->tree[root][i])
            {
                haveChild = true;
                break;
            }
        }
        if (haveChild)
            break;

        // �������ڵ�������ӽڵ㶼��ɾ���ˣ���ɾ������ڵ�
        int preNode = trie->prefix[root];
        trie->tree[preNode][id] = 0;
        trie->prefix[root] = 0;
        root = preNode;
        len--;
    }

    // �ͷ���ʱ�ڴ�
    free(temp);
}