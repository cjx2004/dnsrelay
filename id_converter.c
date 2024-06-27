#include "id_converter.h"
#include <stdlib.h>
#include <string.h>

#define MAX_CLIENTS 65536  // 最大客户端数量

unsigned short currentIndex = 0;  // 当前映射的位置

KeyValue idMapping[MAX_CLIENTS]; // 用于存储id和clientAddr的映射
int isUsed[MAX_CLIENTS]; // 用于记录位置是否被使用

/**
 * 将ID和客户端地址转换并存储映射
 * @param id 客户端的ID
 * @param clientAddr 客户端的地址信息
 * @return 返回存储映射的位置索引
 */
int translate_id(unsigned short id, struct sockaddr_in clientAddr)
{
    int startIndex = currentIndex;
    // 查找一个未被使用的位置
    while (isUsed[currentIndex] == 1)
    {
        currentIndex = (currentIndex + 1) % MAX_CLIENTS;
        // 如果遍历了所有位置都没有找到空闲位置，返回下一个位置
        if (currentIndex == startIndex)
            return startIndex + 1;
    }

    // 保存映射信息
    idMapping[currentIndex].value = currentIndex;
    idMapping[currentIndex].key.id = id;
    idMapping[currentIndex].key.clientAddr = clientAddr;
    isUsed[currentIndex] = 1; // 标记为已使用
    return currentIndex;    // 返回映射的索引值
}

/**
 * 根据存储的位置索引查找原始的ID
 * @param index 存储的位置索引
 * @return 返回原始的ID
 */
unsigned short retrieve_id(unsigned index)
{
    return idMapping[index].key.id;
}

/**
 * 根据存储的位置索引查找原始的客户端地址
 * @param index 存储的位置索引
 * @return 返回原始的客户端地址
 */
struct sockaddr_in retrieve_clientAddr(unsigned index)
{
    return idMapping[index].key.clientAddr;
}

/**
 * 移除指定位置索引的映射
 * @param index 要移除的映射的位置索引
 */
void remove_mapping(unsigned index)
{
    isUsed[index] = 0;
}
