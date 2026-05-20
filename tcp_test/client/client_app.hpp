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

    /// Start the client (blocks until shutdown).
    void run();

    /// Request graceful shutdown from another thread / signal handler.
    void shutdown();

private:
    void runLoop();
    void stdinLoop();

    std::string  m_host;
    uint16_t     m_port;

    std::atomic<bool> m_running;

    // Shared between stdinLoop and runLoop
    std::mutex   m_sendMutex;
    SchannelTLS* m_tls = nullptr;
};
