#pragma once

#include <string>
#include <cstdint>
#include <atomic>
#include <mutex>

class SchannelTLS;

class ClientApp {
public:
    ClientApp(const std::string& host, uint16_t port);
    ~ClientApp() = default;

    ClientApp(const ClientApp&) = delete;
    ClientApp& operator=(const ClientApp&) = delete;

    /// 启动客户端（阻塞直到关闭）。
    void run();

    /// 从另一个线程/信号处理程序请求优雅关闭。
    void shutdown();

private:
    void runLoop();
    void stdinLoop();

    std::string  m_host;
    uint16_t     m_port;

    std::atomic<bool> m_running;

    // 在 stdinLoop 和 runLoop 之间共享
    std::mutex   m_sendMutex;
    SchannelTLS* m_tls = nullptr;
};
