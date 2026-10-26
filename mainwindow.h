#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLineEdit>
#include "Sniffer.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT // 必须有这个宏，才能使用信号和槽

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // 按钮点击响应槽函数
    void onStartClicked();
    void onStopClicked();
    void onClearClicked();
    // 【核心跨线程接收】处理 Sniffer 发来的批量数据包信号
    void onPacketsReceived(QVector<PacketData> packetBatch);

private:
    void setupUI(); // 纯代码搭建界面的辅助函数

    QTableWidget *m_table;   // 显示数据的表格
    QPushButton *m_btnStart; // 开始按钮
    QPushButton *m_btnStop;  // 停止按钮
    QPushButton *m_btnClear; // 清空按钮
    Sniffer *m_sniffer;      // 后台抓包线程实例
    QLineEdit *m_editFilter; // 过滤器输入框
};

#endif // MAINWINDOW_H
