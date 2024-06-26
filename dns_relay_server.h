#ifndef DNS_RELAY_SERVER_H 
#define DNS_RELAY_SERVER_H

#include "trie.h"  // �����ֵ���
#include "cache.h" // �����
#include "dns_msg.h"  // DNS����
#include "msg_convert.h"  // ����ת��
#include "dns_function.h"
#include "debug_info.h"
#include "id_converter.h"

#include <stdio.h>
#include <string.h>
#include <winsock2.h>

#define CACHE_TTL 60   // ���泬ʱʱ��
#define MAX_DOMAIN_LENGTH 512   // ������󳤶�

// ����DNS����ĺ���,���������û���ͨ�ŵ�socket����
void handle_dns_request(struct Trie* trie, struct Cache* cache, SOCKET sock, struct sockaddr_in clientAddr, const char* remoteDnsAddr);

// ����������Ӧ��IP��ַ�ĺ���,���������û���ͨ�ŵ�socket����
unsigned char* findIpAddress(struct Trie* trie, struct Cache* cache, unsigned char domain[MAX_DOMAIN_LENGTH]);

// ����DNS��Ӧ���ĵĺ���
void send_dns_response(int sock, Dns_Msg* msg, struct sockaddr_in clientAddr);

// ת��DNS�����ĵĺ���
void forward_dns_request(int sock, unsigned char* buf, int len, const char* remoteDnsAddr);

// ת��DNS��Ӧ���ĵĺ���
void forward_dns_response(int sock, unsigned char* buf, int len, struct sockaddr_in clientAddr);

#endif