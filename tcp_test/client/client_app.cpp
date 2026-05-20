#include "client_app.hpp"
#include "schannel_tls.hpp"
#include "../protocol/protocol.h"

#include <cstdio>
#include <thread>
#include <chrono>
#include <iostream>
#include <vector>

// ---------------------------------------------------------------------------
// Transport-aware protocol helpers (need a TLS channel)
// ---------------------------------------------------------------------------
static bool recvFull(SchannelTLS& tls, uint8_t* buf, size_t len, int timeoutMs)
{
    size_t received = 0;
    while (received < len) {
        int ret = tls.recv(buf + received, len - received, timeoutMs);
        if (ret <= 0) return false;
        received += ret;
    }
    return true;
}

static MessageHeader recvHeader(SchannelTLS& tls)
{
    MessageHeader hdr = {};
    if (!recvFull(tls, reinterpret_cast<uint8_t*>(&hdr), HEADER_SIZE, 40000)) {
        throw std::runtime_error("Failed to receive header");
    }
    hdr.toHost();
    return hdr;
}

// ---------------------------------------------------------------------------
// ClientApp
// ---------------------------------------------------------------------------
ClientApp::ClientApp(const std::string& host, uint16_t port)
    : m_host(host)
    , m_port(port)
    , m_running(true)
{}

void ClientApp::shutdown()
{
    m_running = false;
}

void ClientApp::run()
{
    std::thread inputThread(&ClientApp::stdinLoop, this);
    runLoop();

    if (inputThread.joinable()) {
        inputThread.join();
    }
    printf("[INFO] Client stopped\n");
}

// ---------------------------------------------------------------------------
// stdin -> send thread
// ---------------------------------------------------------------------------
void ClientApp::stdinLoop()
{
    printf("[INPUT] Type messages (Enter to send, Ctrl+C to quit):\n");

    std::string line;
    while (m_running && std::getline(std::cin, line)) {
        if (line.empty()) continue;

        auto msg = packMessage(MessageType::DATA,
            std::vector<uint8_t>(line.begin(), line.end()));

        {
            std::lock_guard<std::mutex> lock(m_sendMutex);
            if (m_tls && m_tls->isConnected()) {
                int ret = m_tls->send(msg);
                if (ret > 0) {
                    printf("[SEND] %s\n", line.c_str());
                } else {
                    printf("[WARN] Send failed (not connected)\n");
                }
            } else {
                printf("[WARN] Not connected, message dropped\n");
            }
        }
    }
    m_running = false;
}

// ---------------------------------------------------------------------------
// Connection / reconnect loop
// ---------------------------------------------------------------------------
void ClientApp::runLoop()
{
    while (m_running) {
        try {
            SchannelTLS tls;
            printf("[INFO] Connecting to %s:%u ...\n", m_host.c_str(), m_port);
            tls.connect(m_host, m_port);
            printf("[INFO] TLS handshake completed\n");
            
            {
                std::lock_guard<std::mutex> lock(m_sendMutex);
                m_tls = &tls;
            }

            auto hello = packMessage(MessageType::DATA,
                std::vector<uint8_t>({'H', 'e', 'l', 'l', 'o'}));
            tls.send(hello);

            while (m_running) {
                MessageHeader hdr = recvHeader(tls);
                std::vector<uint8_t> payload;

                if (hdr.length > 0 && hdr.length <= MAX_PAYLOAD_SIZE) {
                    payload.resize(hdr.length);
                    if (!recvFull(tls, payload.data(), hdr.length, 10000)) {
                        printf("[WARN] Failed to receive payload\n");
                        break;
                    }
                }

                switch (static_cast<uint32_t>(hdr.type)) {
                case static_cast<uint32_t>(MessageType::HEARTBEAT):
                    printf("[HEARTBEAT] <- server\n");
                    break;

                case static_cast<uint32_t>(MessageType::DATA):
                    printf("[DATA] from server: %.*s\n",
                        (int)payload.size(), payload.data());
                    break;

                case static_cast<uint32_t>(MessageType::COMMAND):
                    printf("[CMD] from server: %.*s\n",
                        (int)payload.size(), payload.data());
                    {
                        auto resp = packMessage(MessageType::RESPONSE,
                            std::vector<uint8_t>({'O', 'K'}));
                        tls.send(resp);
                    }
                    break;

                case static_cast<uint32_t>(MessageType::RESPONSE):
                    printf("[RESP] from server: %.*s\n",
                        (int)payload.size(), payload.data());
                    break;

                default:
                    printf("[UNKNOWN] type=0x%04X\n", hdr.type);
                    break;
                }
            }
        }
        catch (const std::exception& e) {
            fprintf(stderr, "[ERROR] %s\n", e.what());
        }

        {
            std::lock_guard<std::mutex> lock(m_sendMutex);
            m_tls = nullptr;
        }

        if (m_running) {
            printf("[INFO] Reconnecting in 5 seconds...\n");
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}
