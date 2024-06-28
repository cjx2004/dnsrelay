#ifndef _DIC_TREE_H_
#define _DIC_TREE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_NODE 1000001   // Trie树的最大节点数
#define MAX_ALPHABET 26 + 10 + 2   // 字母表大小，包括小写字母、数字和特殊字符

struct Node // 域名节点结构体
{
    char domain[512]; // 存储域名的数组
    struct Node* next; // 指向下一个节点的指针
};

struct Trie // Trie树结构体
{
    int tree[MAX_NODE][MAX_ALPHABET]; // Trie树的节点结构
    int prefix[MAX_NODE];             // 每个节点的前缀
    bool isEnd[MAX_NODE];             // 标记节点是否是单词结尾
    int size;                         // Trie树中节点的总数
    unsigned char toIp[MAX_NODE][4];  // 存储IP地址的数组
};

// 初始化Trie树
void initializeTrie(struct Trie* trie);

// 从dnsrelay.txt文件中读取域名和IP地址，并插入到Trie树中
void loadLocalTableEntries(struct Trie* trie);

// 将域名简化，即将域名中的大写字母转换成小写字母
void convertToLowerCase(char domain[]);

// 将域名插入到Trie树中
void insertDomainNode(struct Trie* trie, const char domain[], unsigned char ipAddr[4]);

// 删除域名及其对应的IP地址
void eraseDomainNode(struct Trie* trie, const unsigned char domain[]);

// 查找一个域名在Trie树中对应的IP地址，返回节点值，根据toIp找IP地址
int searchDomainNode(struct Trie* trie, const unsigned char domain[]);

#endif // _TRIE_H_
