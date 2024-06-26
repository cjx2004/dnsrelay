#include "murmurhash.h"

// ��FMIX32дΪ����
static inline uint32_t fmix32(uint32_t hash)
{
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash;
}

uint32_t MurmurHash(const void* key, size_t length, uint32_t seed)
{
    const uint32_t multiplier = 0x5bd1e995;
    const int shift = 24;
    const uint8_t* data = (const uint8_t*)key;
    uint32_t hash = seed ^ length;

    // ����ÿ��4�ֽڿ�
    while (length >= 4)
    {
        uint32_t k = *(uint32_t*)data;
        k *= multiplier;
        k ^= k >> shift;
        k *= multiplier;
        hash *= multiplier;
        hash ^= k;
        data += 4;
        length -= 4;
    }

    // ����ʣ����ֽ�
    switch (length)
    {
    case 3:
        hash ^= data[2] << 16;
    case 2:
        hash ^= data[1] << 8;
    case 1:
        hash ^= data[0];
        hash *= multiplier;
    }

    // �������ջ���
    hash = fmix32(hash);
    return hash;
}
