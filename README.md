# Mini-Wireshark

基于 Qt 和 libpcap 开发的 Linux 桌面端轻量级网络抓包分析工具。项目采用 UI 与抓包逻辑分离的多线程架构，支持 BPF 语法过滤与底层报文解析，解决了高并发网络流量下的界面卡顿问题。

**核心特性**

* **多线程抓包**：抓包引擎继承自 `QThread`，在独立子线程中执行 `pcap_loop` 阻塞式监听，确保主 UI 线程持续流畅。
* **极致 UI 防卡顿**：内置数据包缓冲队列，默认积攒 50 个报文后通过跨线程信号批量 `emit`。配合 `setUpdatesEnabled` 暂停表格底层重绘，实现大流量下的命令式平滑滚屏。
* **协议深度解析**：利用 C++ `pragma pack` 结构体内存映射，精准切片并解析 Ethernet、IPv4、TCP、UDP 及 ICMP 头部。
* **BPF 动态过滤**：支持在界面直接输入 BPF 字节码规则（如 `tcp port 80`、`icmp`）进行底层内核级流量过滤。

**环境依赖**

* 操作系统：Ubuntu Linux (或支持 libpcap 的类 Unix 系统)
* 开发框架：Qt 5 / Qt 6 (需 Core, Gui, Widgets 模块)
* 核心库：libpcap (`sudo apt-get install libpcap-dev`)
* 编译器：支持 C++11 及以上标准的 GCC/Clang

**项目结构**

* `Protocol.h`：定义底层网络协议的帧头结构体与数据传输模型。
* `Sniffer.h/cpp`：后台抓包核心线程，负责网卡设备启停、BPF 规则注入与原始报文解析。
* `mainwindow.h/cpp`：主界面逻辑，处理跨线程信号接收、数据表格批量渲染及清空重置。
* `main.cpp`：程序入口与 Qt 事件循环。

**编译与运行**
在终端中进入项目根目录，依次执行以下命令：

```bash
# 1. 生成 Makefile 并编译
qmake
make

# 2. 运行程序（监听网卡需要 Root 权限）
sudo ./NetAnalyzer

```

**使用说明**

1. 启动程序后，在输入框中填入可选的 BPF 过滤规则。
2. 点击 **开始抓包**，程序将自动监听默认网卡（代码中指定，如 `wlp0s20f3`）并实时渲染数据。
3. 点击 **停止抓包** 结束监听，可点击 **清空列表** 清除当前表格数据。
