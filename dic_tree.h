#ifndef _DIC_TREE_H_
#define _DIC_TREE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_NODE 1000001   // Trie�������ڵ���
#define MAX_ALPHABET 26 + 10 + 2   // ��ĸ���С������Сд��ĸ�����ֺ������ַ�

struct Node // �����ڵ�ṹ��
{
    char domain[512]; // �洢����������
    struct Node* next; // ָ����һ���ڵ��ָ��
};

struct Trie // Trie���ṹ��
{
    int tree[MAX_NODE][MAX_ALPHABET]; // Trie���Ľڵ�ṹ
    int prefix[MAX_NODE];             // ÿ���ڵ��ǰ׺
    bool isEnd[MAX_NODE];             // ��ǽڵ��Ƿ��ǵ��ʽ�β
    int size;                         // Trie���нڵ������
    unsigned char toIp[MAX_NODE][4];  // �洢IP��ַ������
};

// ��ʼ��Trie��
void initializeTrie(struct Trie* trie);

// ��dnsrelay.txt�ļ��ж�ȡ������IP��ַ�������뵽Trie����
void loadLocalTableEntries(struct Trie* trie);

// �������򻯣����������еĴ�д��ĸת����Сд��ĸ
void convertToLowerCase(char domain[]);

// ���������뵽Trie����
void insertDomainNode(struct Trie* trie, const char domain[], unsigned char ipAddr[4]);

// ɾ�����������Ӧ��IP��ַ
void eraseDomainNode(struct Trie* trie, const unsigned char domain[]);

// ����һ��������Trie���ж�Ӧ��IP��ַ�����ؽڵ�ֵ������toIp��IP��ַ
int searchDomainNode(struct Trie* trie, const unsigned char domain[]);

#endif // _TRIE_H_
