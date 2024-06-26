#ifndef _TRIE_H_
#define _TRIE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_NODE 1000001
#define MAX_ALPHABET 26 + 10 + 2

struct Node // �����ڵ�
{
    char domain[512]; // ����
    struct Node* next;
};

struct Trie // Trie��
{
    int tree[MAX_NODE][MAX_ALPHABET]; // �ֵ���
    int prefix[MAX_NODE];             // ǰ׺
    bool isEnd[MAX_NODE];             // �Ƿ��ǵ��ʽ�β
    int size;                         // �ܽڵ���
    unsigned char toIp[MAX_NODE][4];  // IP��ַ
};

// ��ʼ��Trie��
void initTrie(struct Trie* trie);

// ��dnsrelay.txt�ļ��ж�ȡ������IP��ַ,�����뵽Trie����
void loadLocalTable(struct Trie* trie);

// ��������,���������еĴ�д��ĸת����Сд��ĸ
void simplifyDomain(char domain[]);

// ���������뵽Trie����
void insertNode(struct Trie* trie, const char domain[], unsigned char ipAddr[4]);

// ɾ������
void deleteNode(struct Trie* trie, const unsigned char domain[]);

// ��������
int findNode(struct Trie* trie, const unsigned char domain[]);

#endif // _TRIE_H_