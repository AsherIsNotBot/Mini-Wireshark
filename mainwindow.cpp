#include "mainwindow.h"
#include <QHeaderView>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_sniffer(new Sniffer(this))
{
    setupUI(); // 初始化界面

    // 1. 绑定按钮点击信号与槽
    connect(m_btnStart, &QPushButton::clicked, this, &MainWindow::onStartClicked);
    connect(m_btnStop, &QPushButton::clicked, this, &MainWindow::onStopClicked);
    connect(m_btnClear, &QPushButton::clicked, this, &MainWindow::onClearClicked);

    // 2. 【核心架构打通】将子线程的批量发送信号，连接到主线程的处理槽函数
    // 只要 Sniffer 攒够了 50 个包并 emit packetsParsed，就会自动触发此函数
    connect(m_sniffer, &Sniffer::packetsParsed, this, &MainWindow::onPacketsReceived);
}

MainWindow::~MainWindow()
{
    m_sniffer->stopSniffing(); // 关闭窗口前，确保安全杀死抓包线程
}

void MainWindow::setupUI()
{
    // 搭建主窗口的基础布局
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(centralWidget);

    m_btnStart = new QPushButton("开始抓包", this);
    m_btnStop = new QPushButton("停止抓包", this);
    m_btnStop->setEnabled(false); // 刚启动时停止按钮置灰
    m_btnClear = new QPushButton("清空列表", this);

    m_editFilter = new QLineEdit(this);
    m_editFilter->setPlaceholderText("输入 BPF 过滤 规则（例如：icmp 或 tcp port 80）");
    layout->addWidget(m_editFilter);

    // 初始化表格 (0 行, 6 列)
    m_table = new QTableWidget(0, 6, this);
    QStringList headers = {"序号", "时间", "源 IP", "目的 IP", "协议", "长度"};
    m_table->setHorizontalHeaderLabels(headers);

    // 让表格列宽自动拉伸填满屏幕
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // 整行选中模式
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);

    layout->addWidget(m_btnStart);
    layout->addWidget(m_btnStop);
    layout->addWidget(m_btnClear);
    layout->addWidget(m_table);

    setCentralWidget(centralWidget);
    resize(900, 600); // 默认窗口大小
}

void MainWindow::onStartClicked()
{
    m_btnStart->setEnabled(false);
    m_btnStop->setEnabled(true);
    m_editFilter->setEnabled(false);

    QString filterStr = m_editFilter->text();

    // 传入 网卡名称
    m_sniffer->startSniffing("wlp0s20f3",filterStr);

}

void MainWindow::onStopClicked()
{
    m_btnStart->setEnabled(true);
    m_btnStop->setEnabled(false);
    m_editFilter->setEnabled(true);
    m_sniffer->stopSniffing();
}

void MainWindow::onClearClicked()
{
    m_table->setRowCount(0);
}

// 消费者提取数据并渲染 UI 的核心逻辑
void MainWindow::onPacketsReceived(QVector<PacketData> packetBatch)
{
    // 暂停表格的底层绘制。如果不加这句，每插入一行 Qt 就会重绘一次整个表格，遇到突发流量瞬间卡死！
    m_table->setUpdatesEnabled(false);

    // 遍历这批接收到的 50 个包
    for (const auto& data : packetBatch) {
        int row = m_table->rowCount(); // 获取当前表格有多少行
        m_table->insertRow(row);       // 在末尾新加一行

        // 往这一行的各个格子里填数据
        m_table->setItem(row, 0, new QTableWidgetItem(QString::number(data.id)));
        m_table->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(data.timeStr)));
        m_table->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(data.srcIp)));
        m_table->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(data.destIp)));
        m_table->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(data.protocol)));
        m_table->setItem(row, 5, new QTableWidgetItem(QString::number(data.length)));
    }

    // 将表格滚动条强制拉到最底部，实现类似命令行的自动滚屏效果
    m_table->scrollToBottom();

    // 数据全部插入完毕，恢复底层绘制，一次性将 50 行渲染出来
    m_table->setUpdatesEnabled(true);
}
