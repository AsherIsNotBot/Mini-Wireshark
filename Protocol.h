#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>

#pragma pack(push,1)

// 以太网帧头（14字节）
struct EthHeader
{
    uint8_t dest_mac[6]; // 目的 MAC
    uint8_t src_mac[6]; // 源 MAC
    uint16_t eth_type; // 协议类型
};

// IPv4 报文头（20字节）
struct IPv4Header{
    uint8_t version_ihl; // 版本号和头部
    uint8_t tos; // 服务类型
    uint16_t total_length; // 总长度
    uint16_t id; // 标识符
    uint16_t frag_offset; // 标志和偏移
    uint8_t ttl; // 存活时间
    uint8_t protocol; // 上层协议（6 为TCP，17为UDP，1为ICMP）
    uint16_t checksum; // 检验和
    uint32_t src_ip;  // 【修正】源 IP（大端序），必须为 uint32_t
    uint32_t dest_ip; // 【修正】目标 IP，必须为 uint32_t
};

// TCP 报文头
struct TCPHeader
{
    uint16_t src_port; // 源端口
    uint16_t dest_port; // 目的端口
};

// UDP 报文头
struct UDPHeader
{
    uint16_t src_port;
    uint16_t dest_port;
};

#pragma pack(pop)

#include <string>

// 解析后的数据包信息载体
struct PacketData
{
    int id; // 序号
    int length; // 真实长度
    std::string timeStr; // 抓包时间
    std::string srcIp;   // 【修正】统一为 srcIp
    std::string destIp;  // 目的 IP
    std::string protocol;  // 协议名称
    uint16_t srcPort;    // 【修正】统一驼峰命名为 srcPort
    uint16_t destPort;   // 【修正】统一驼峰命名为 destPort
};

#endif // PROTOCOL_H
