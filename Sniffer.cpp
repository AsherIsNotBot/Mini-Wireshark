#include "Sniffer.h"
#include <QDebug>
#include <arpa/inet.h>
#include <QDateTime>

Sniffer::Sniffer(QObject *parent)
    : QThread(parent), m_handle(nullptr), m_isRunning(false), m_packetCount(0)
{
    // 向 Qt 系统注册我们的自定义类型，这一步是跨线程传递数组的必须操作！
    qRegisterMetaType<QVector<PacketData>>("QVector<PacketData>");
}

Sniffer::~Sniffer() {
    stopSniffing();
}

void Sniffer::startSniffing(const QString& deviceName,const QString& filterRules) {
    m_device = deviceName;
    m_filter = filterRules;
    m_isRunning = true;
    m_packetCount = 0;
    m_buffer.clear();
    start(); // 这一句会触发底层开启一个新线程，并自动调用 run()
}

void Sniffer::stopSniffing() {
    m_isRunning = false;
    if (m_handle) {
        pcap_breakloop(m_handle); // 强行打破 pcap_loop 的死循环
    }
    quit(); // 退出线程事件循环
    wait(); // 阻塞等待线程安全结束
}

void Sniffer::run() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1. 打开网卡
    m_handle = pcap_open_live(m_device.toStdString().c_str(), 65535, 1, 1000, errbuf);
    if (!m_handle) {
        qDebug() << "无法打开网卡:" << errbuf;
        return;
    }

    qDebug() << "开始在子线程监听网卡:" << m_device;

    if(!m_filter.isEmpty()){
        struct bpf_program bpf;
        // 1. 将字符串规则编译为 BPF 字节码
        // 参数：句柄, bpf结构体, C风格字符串规则, 优化选项, 子网掩码(这里填未知即可)
        if (pcap_compile(m_handle, &bpf, m_filter.toStdString().c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
            qDebug() << "过滤器编译失败:" << pcap_geterr(m_handle);
            pcap_close(m_handle);
            return; // 规则写错了，直接退出线程
        }

        // 2. 将编译好的字节码注入抓包底层
        if (pcap_setfilter(m_handle, &bpf) < 0) {
            qDebug() << "过滤器设置失败:" << pcap_geterr(m_handle);
        }

        // 3. 释放编译产生的临时内存
        pcap_freecode(&bpf);
    }

    // 2. 开启死循环抓包
    // 这里的神仙操作：把 this 指针（当前 Sniffer 对象）作为 userData 传给静态回调函数
    pcap_loop(m_handle, -1, packetHandler, reinterpret_cast<u_char*>(this));

    pcap_close(m_handle);
    m_handle = nullptr;
}

// 静态回调函数，网卡每抓到一个包都会自动进这里
void Sniffer::packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // 把 userData 强转回 Sniffer 实例指针，这样我们才能调用类的成员函数
    Sniffer *sniffer = reinterpret_cast<Sniffer*>(userData);

    // 如果没有被要求停止，就去解析这个包
    if (sniffer->m_isRunning) {
        sniffer->parsePacket(pkthdr, packet);
    }
}

// 核心解剖逻辑（从昨天纯 C++ 控制台移植过来的）
void Sniffer::parsePacket(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PacketData data;
    data.id = ++m_packetCount;
    data.length = pkthdr->len;
    data.timeStr = QDateTime::currentDateTime().toString("HH:mm:ss.zzz").toStdString();

    // 1. 切以太网头
    const EthHeader *eth = reinterpret_cast<const EthHeader*>(packet);
    uint16_t eth_type = ntohs(eth->eth_type);

    if (eth_type == 0x0800) { // IPv4
        // 2. 切 IP 头
        const IPv4Header *ip = reinterpret_cast<const IPv4Header*>(packet + sizeof(EthHeader));
        int ip_header_len = (ip->version_ihl & 0x0F) * 4;

        struct in_addr src, dest;
        src.s_addr = ip->src_ip;
        dest.s_addr = ip->dest_ip;

        data.srcIp = inet_ntoa(src);
        data.destIp = inet_ntoa(dest);

        // 3. 切传输层
        const u_char *transport_payload = packet + sizeof(EthHeader) + ip_header_len;

        if (ip->protocol == 6) { // TCP
            const TCPHeader *tcp = reinterpret_cast<const TCPHeader*>(transport_payload);
            data.protocol = "TCP";
            data.srcPort = ntohs(tcp->src_port);
            data.destPort = ntohs(tcp->dest_port);
        } else if (ip->protocol == 17) { // UDP
            const UDPHeader *udp = reinterpret_cast<const UDPHeader*>(transport_payload);
            data.protocol = "UDP";
            data.srcPort = ntohs(udp->src_port);
            data.destPort = ntohs(udp->dest_port);
        } else if (ip->protocol == 1) {
            data.protocol = "ICMP";
        } else {
            data.protocol = "IPv4 (Other)";
        }
    } else {
        data.protocol = "Non-IPv4";
    }

    // ==== 【简历高光时刻：队列缓冲防卡顿】 ====
    m_buffer.append(data);

    // 当积攒了 50 个包，就把这 50 个包打包作为一次信号发送给 UI 线程
    if (m_buffer.size() >= 50) {
        emit packetsParsed(m_buffer);
        m_buffer.clear(); // 清空缓存，准备装下一批
    }
}
