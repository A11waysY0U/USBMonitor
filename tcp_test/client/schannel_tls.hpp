#pragma once

#define SECURITY_WIN32
#define UNICODE
#define _UNICODE

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <sspi.h>

#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <cstdint>

class SchannelTLS {
public:
    SchannelTLS();
    ~SchannelTLS();

    SchannelTLS(const SchannelTLS&) = delete;
    SchannelTLS& operator=(const SchannelTLS&) = delete;

    void connect(const std::string& host, uint16_t port);
    void disconnect();

    int send(const std::vector<uint8_t>& data);
    int send(const uint8_t* data, size_t len);
    int recv(std::vector<uint8_t>& buf, int timeoutMs = 5000);
    int recv(uint8_t* buf, size_t bufSize, int timeoutMs = 5000);

    bool isConnected() const { return m_connected; }

    static void initWinsock();
    static void cleanupWinsock();

private:
    void tcpConnect(const std::string& host, uint16_t port);
    void performHandshake(const std::string& host);

    SecPkgContext_StreamSizes queryStreamSizes();

    static std::string wideToUtf8(const wchar_t* wstr);

    CredHandle  m_hCred;
    CtxtHandle  m_hContext;
    SOCKET      m_socket;
    bool        m_connected;
    bool        m_contextValid;

    SecPkgContext_StreamSizes m_streamSizes;
    bool m_streamSizesQueried;

    std::vector<uint8_t> m_recvBuf;
    std::vector<uint8_t> m_extraBuf;
};

