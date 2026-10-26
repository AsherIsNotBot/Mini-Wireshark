#ifndef SNIFFER_H
#define SNIFFER_H

#include <QThread>
#include <QString>
#include <QVector>
#include <atomic>
#include <pcap.h>
#include "Protocol.h" // 引入协议的struct

// 注册 QVector<PacketData> 类型，让 Qt 的信号槽支持传递整个数组
Q_DECLARE_METATYPE(QVector<PacketData>)

class Sniffer : public QThread
{
    Q_OBJECT // 开启 Qt 信号槽机制的宏

public:
    explicit Sniffer(QObject *parent = nullptr);
    ~Sniffer();

    // 控制抓包的开关
    void startSniffing(const QString& deviceName,const QString& fileterRules = "");
    void stopSniffing();

signals:
    // 【核心跨线程通信信号】一次性把一批解析好的包扔给 UI 线程
    void packetsParsed(QVector<PacketData> packetBatch);

protected:
    // 重写 QThread 的 run 函数，这个函数里的代码会运行在子线程中
    void run() override;

private:
    // libpcap 的 C 语言回调函数，必须是静态的
    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

    // 解析具体报文的内部函数
    void parsePacket(const struct pcap_pkthdr *pkthdr, const u_char *packet);

private:
    QString m_device;               // 要抓取的网卡名
    QString m_filter;               // 当前过滤规则
    pcap_t *m_handle;               // 抓包句柄
    std::atomic<bool> m_isRunning;  // 线程安全的开关变量

    QVector<PacketData> m_buffer;   // 【性能关键】包缓存队列
    int m_packetCount;              // 记录总抓包数
};

#endif // SNIFFER_H
