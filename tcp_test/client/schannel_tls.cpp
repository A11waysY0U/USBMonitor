#include "schannel_tls.hpp"
#include <cstdio>

SchannelTLS::SchannelTLS()
    : m_socket(INVALID_SOCKET)
    , m_connected(false)
    , m_contextValid(false)
    , m_streamSizesQueried(false)
{
    SecInvalidateHandle(&m_hCred);
    SecInvalidateHandle(&m_hContext);
    memset(&m_streamSizes, 0, sizeof(m_streamSizes));
}

SchannelTLS::~SchannelTLS()
{
    disconnect();
}

void SchannelTLS::initWinsock()
{
    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        throw std::runtime_error("WSAStartup failed: " + std::to_string(ret));
    }
}

void SchannelTLS::cleanupWinsock()
{
    WSACleanup();
}

void SchannelTLS::tcpConnect(const std::string& host, uint16_t port)
{
    struct addrinfo hints, *result = nullptr, *ptr = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string portStr = std::to_string(port);
    int ret = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
    if (ret != 0) {
        throw std::runtime_error("getaddrinfo failed: " + std::to_string(ret));
    }

    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        m_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (m_socket == INVALID_SOCKET) continue;

        if (::connect(m_socket, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
            break;
        }

        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }

    freeaddrinfo(result);

    if (m_socket == INVALID_SOCKET) {
        throw std::runtime_error("Failed to connect to " + host + ":" + portStr);
    }
}

void SchannelTLS::connect(const std::string& host, uint16_t port)
{
    tcpConnect(host, port);
    performHandshake(host);
    m_connected = true;
}

void SchannelTLS::performHandshake(const std::string& host)
{
    SCHANNEL_CRED cred = {};
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION
                 | SCH_CRED_NO_DEFAULT_CREDS
                 | SCH_CRED_NO_SERVERNAME_CHECK;

    SecInvalidateHandle(&m_hCred);

    TimeStamp tsExpiry;
    SECURITY_STATUS secStatus = AcquireCredentialsHandleW(
        nullptr,
        const_cast<LPWSTR>(UNISP_NAME),
        SECPKG_CRED_OUTBOUND,
        nullptr,
        &cred,
        nullptr,
        nullptr,
        &m_hCred,
        &tsExpiry
    );

    if (secStatus != SEC_E_OK) {
        throw std::runtime_error("AcquireCredentialsHandle failed: 0x"
            + std::to_string(secStatus));
    }

    SecInvalidateHandle(&m_hContext);

    SecBufferDesc outBufDesc;
    SecBuffer     outSecBuf;
    DWORD         dwSSPIOutFlags = 0;
    DWORD         dwSSPIInFlags =
        ISC_REQ_SEQUENCE_DETECT   |
        ISC_REQ_REPLAY_DETECT     |
        ISC_REQ_CONFIDENTIALITY   |
        ISC_RET_EXTENDED_ERROR    |
        ISC_REQ_ALLOCATE_MEMORY   |
        ISC_REQ_STREAM;

    outBufDesc.ulVersion = SECBUFFER_VERSION;
    outBufDesc.cBuffers  = 1;
    outBufDesc.pBuffers  = &outSecBuf;

    outSecBuf.BufferType = SECBUFFER_TOKEN;
    outSecBuf.pvBuffer   = nullptr;
    outSecBuf.cbBuffer   = 0;


    SecBufferDesc inBufDesc;
    SecBuffer     inSecBufs[2];
    bool          firstLoop = true;
    bool          done      = false;

    std::wstring targetName(host.begin(), host.end());

    while (!done) {
        secStatus = InitializeSecurityContextW(
            &m_hCred,
            firstLoop ? nullptr : &m_hContext,
            const_cast<SEC_WCHAR*>(reinterpret_cast<const SEC_WCHAR*>(targetName.c_str())),
            dwSSPIInFlags,
            0,
            SECURITY_NATIVE_DREP,
            firstLoop ? nullptr : &inBufDesc,
            0,
            &m_hContext,
            &outBufDesc,
            &dwSSPIOutFlags,
            &tsExpiry
        );

        if (secStatus == SEC_I_COMPLETE_NEEDED || secStatus == SEC_I_COMPLETE_AND_CONTINUE) {
            CompleteAuthToken(&m_hContext, &outBufDesc);
        }

        if (firstLoop) {
            m_contextValid = true;
        }

        if (outSecBuf.cbBuffer > 0 && outSecBuf.pvBuffer != nullptr) {
            int sent = ::send(m_socket,
                reinterpret_cast<const char*>(outSecBuf.pvBuffer),
                (int)outSecBuf.cbBuffer, 0);
            if (sent <= 0) {
                FreeContextBuffer(outSecBuf.pvBuffer);
                throw std::runtime_error("Handshake send failed");
            }
            FreeContextBuffer(outSecBuf.pvBuffer);
            outSecBuf.pvBuffer = nullptr;
        }

        if (secStatus == SEC_E_OK) {
            done = true;
        }
        else if (secStatus == SEC_I_CONTINUE_NEEDED) {
            uint8_t recvBuf[16384];
            int recvd = ::recv(m_socket, reinterpret_cast<char*>(recvBuf), sizeof(recvBuf), 0);
            if (recvd <= 0) {
                throw std::runtime_error("Handshake recv failed");
            }

            inBufDesc.ulVersion = SECBUFFER_VERSION;
            inBufDesc.cBuffers  = 2;
            inBufDesc.pBuffers  = inSecBufs;

            inSecBufs[0].BufferType = SECBUFFER_TOKEN;
            inSecBufs[0].pvBuffer   = recvBuf;
            inSecBufs[0].cbBuffer   = (ULONG)recvd;

            inSecBufs[1].BufferType = SECBUFFER_EMPTY;
            inSecBufs[1].pvBuffer   = nullptr;
            inSecBufs[1].cbBuffer   = 0;

            firstLoop = false;
        }
        else {
            throw std::runtime_error("InitializeSecurityContext unexpected status: 0x"
                + std::to_string(secStatus));
        }
    }

    queryStreamSizes();
}

SecPkgContext_StreamSizes SchannelTLS::queryStreamSizes()
{
    SecPkgContext_StreamSizes sizes = {};
    SECURITY_STATUS secStatus = QueryContextAttributesW(
        &m_hContext, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (secStatus != SEC_E_OK) {
        throw std::runtime_error("QueryContextAttributes(StreamSizes) failed: 0x"
            + std::to_string(secStatus));
    }
    m_streamSizes = sizes;
    m_streamSizesQueried = true;
    return sizes;
}

void SchannelTLS::disconnect()
{
    if (!m_connected) return;
    m_connected = false;

    m_recvBuf.clear();
    m_extraBuf.clear();

    if (m_contextValid) {
        SecBufferDesc outBufDesc;
        SecBuffer     outSecBuf;

        outBufDesc.ulVersion = SECBUFFER_VERSION;
        outBufDesc.cBuffers  = 1;
        outBufDesc.pBuffers  = &outSecBuf;

        outSecBuf.BufferType = SECBUFFER_TOKEN;
        outSecBuf.pvBuffer   = nullptr;
        outSecBuf.cbBuffer   = 0;

        DWORD dwFlags = 0;
        TimeStamp ts;

        SECURITY_STATUS secStatus = ApplyControlToken(&m_hContext, &outBufDesc);
        (void)secStatus;
        secStatus = InitializeSecurityContextW(
            &m_hCred,
            &m_hContext,
            nullptr,
            dwFlags,
            0,
            SECURITY_NATIVE_DREP,
            nullptr,
            0,
            &m_hContext,
            &outBufDesc,
            &dwFlags,
            &ts
        );

        if (outSecBuf.cbBuffer > 0 && outSecBuf.pvBuffer != nullptr) {
            ::send(m_socket,
                reinterpret_cast<const char*>(outSecBuf.pvBuffer),
                (int)outSecBuf.cbBuffer, 0);
            FreeContextBuffer(outSecBuf.pvBuffer);
        }

        DeleteSecurityContext(&m_hContext);
        SecInvalidateHandle(&m_hContext);
        m_contextValid = false;
    }

    if (SecIsValidHandle(&m_hCred)) {
        FreeCredentialsHandle(&m_hCred);
        SecInvalidateHandle(&m_hCred);
    }

    if (m_socket != INVALID_SOCKET) {
        shutdown(m_socket, SD_BOTH);
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
}

int SchannelTLS::send(const std::vector<uint8_t>& data)
{
    return send(data.data(), data.size());
}

int SchannelTLS::send(const uint8_t* data, size_t len)
{
    if (!m_connected || !m_streamSizesQueried) return -1;

    size_t headerSize  = m_streamSizes.cbHeader;
    size_t trailerSize = m_streamSizes.cbTrailer;
    size_t maxChunk    = m_streamSizes.cbMaximumMessage;

    if (maxChunk == 0) return -1;

    int totalSent = 0;
    size_t pos = 0;

    while (pos < len) {
        size_t chunkSize = len - pos;
        if (chunkSize > maxChunk) chunkSize = maxChunk;

        std::vector<uint8_t> sendBuf(headerSize + chunkSize + trailerSize);

        SecBufferDesc msgDesc;
        SecBuffer     msgBufs[4];

        msgDesc.ulVersion = SECBUFFER_VERSION;
        msgDesc.cBuffers  = 4;
        msgDesc.pBuffers  = msgBufs;

        msgBufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        msgBufs[0].pvBuffer   = sendBuf.data();
        msgBufs[0].cbBuffer   = (ULONG)headerSize;

        msgBufs[1].BufferType = SECBUFFER_DATA;
        msgBufs[1].pvBuffer   = sendBuf.data() + headerSize;
        msgBufs[1].cbBuffer   = (ULONG)chunkSize;
        memcpy(msgBufs[1].pvBuffer, data + pos, chunkSize);

        msgBufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        msgBufs[2].pvBuffer   = sendBuf.data() + headerSize + chunkSize;
        msgBufs[2].cbBuffer   = (ULONG)trailerSize;

        msgBufs[3].BufferType = SECBUFFER_EMPTY;
        msgBufs[3].pvBuffer   = nullptr;
        msgBufs[3].cbBuffer   = 0;

        SECURITY_STATUS secStatus = EncryptMessage(&m_hContext, 0, &msgDesc, 0);
        if (secStatus != SEC_E_OK) {
            return -1;
        }

        int actualSendSize = (int)(msgBufs[0].cbBuffer + msgBufs[1].cbBuffer + msgBufs[2].cbBuffer);
        int toSend = actualSendSize;
        int sentTotal = 0;
        while (sentTotal < toSend) {
            int sent = ::send(m_socket, reinterpret_cast<const char*>(sendBuf.data()) + sentTotal, toSend - sentTotal, 0);
            if (sent <= 0) {
                return -1;
            }
            sentTotal += sent;
        }

        totalSent += (int)chunkSize;
        pos += chunkSize;
    }

    return totalSent;
}

int SchannelTLS::recv(std::vector<uint8_t>& buf, int timeoutMs)
{
    buf.resize(65536);
    int ret = recv(buf.data(), buf.size(), timeoutMs);
    if (ret > 0) {
        buf.resize(ret);
    } else {
        buf.clear();
    }
    return ret;
}

int SchannelTLS::recv(uint8_t* buf, size_t bufSize, int timeoutMs)
{
    if (!m_connected) return -1;

    if (!m_recvBuf.empty()) {
        size_t copyLen = m_recvBuf.size() < bufSize ? m_recvBuf.size() : bufSize;
        memcpy(buf, m_recvBuf.data(), copyLen);
        m_recvBuf.erase(m_recvBuf.begin(), m_recvBuf.begin() + copyLen);
        return (int)copyLen;
    }

    if (timeoutMs > 0) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_socket, &fds);

        struct timeval tv;
        tv.tv_sec  = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        int selRet = select(0, &fds, nullptr, nullptr, &tv);
        if (selRet <= 0) return selRet;
    }

    uint8_t rawBuf[65536];
    int rawLen = 0;

    if (!m_extraBuf.empty()) {
        rawLen = (int)(m_extraBuf.size() < sizeof(rawBuf) ? m_extraBuf.size() : sizeof(rawBuf));
        memcpy(rawBuf, m_extraBuf.data(), rawLen);
        m_extraBuf.erase(m_extraBuf.begin(), m_extraBuf.begin() + rawLen);
    }

    int more = ::recv(m_socket, reinterpret_cast<char*>(rawBuf) + rawLen, (int)(sizeof(rawBuf) - rawLen), 0);
    if (more < 0) return -1;
    if (more == 0 && rawLen == 0) return 0;
    rawLen += more;

    SecBufferDesc msgDesc;
    SecBuffer     msgBufs[4];

    msgDesc.ulVersion = SECBUFFER_VERSION;
    msgDesc.cBuffers  = 4;
    msgDesc.pBuffers  = msgBufs;

    msgBufs[0].BufferType = SECBUFFER_DATA;
    msgBufs[0].pvBuffer   = rawBuf;
    msgBufs[0].cbBuffer   = (ULONG)rawLen;

    msgBufs[1].BufferType = SECBUFFER_EMPTY;
    msgBufs[1].pvBuffer   = nullptr;
    msgBufs[1].cbBuffer   = 0;

    msgBufs[2].BufferType = SECBUFFER_EMPTY;
    msgBufs[2].pvBuffer   = nullptr;
    msgBufs[2].cbBuffer   = 0;

    msgBufs[3].BufferType = SECBUFFER_EMPTY;
    msgBufs[3].pvBuffer   = nullptr;
    msgBufs[3].cbBuffer   = 0;

    SECURITY_STATUS secStatus = DecryptMessage(&m_hContext, &msgDesc, 0, nullptr);

    while (secStatus == SEC_E_INCOMPLETE_MESSAGE) {
        int more = ::recv(m_socket,
            reinterpret_cast<char*>(rawBuf) + rawLen,
            (int)(sizeof(rawBuf) - rawLen), 0);
        if (more <= 0) return -1;

        rawLen += more;

        msgBufs[0].cbBuffer = (ULONG)rawLen;
        msgBufs[1].BufferType = SECBUFFER_EMPTY;
        msgBufs[2].BufferType = SECBUFFER_EMPTY;
        msgBufs[3].BufferType = SECBUFFER_EMPTY;

        secStatus = DecryptMessage(&m_hContext, &msgDesc, 0, nullptr);
    }

    if (secStatus != SEC_E_OK) {
        return -1;
    }

    for (int i = 0; i < 4; i++) {
        if (msgBufs[i].BufferType == SECBUFFER_DATA && msgBufs[i].pvBuffer && msgBufs[i].cbBuffer > 0) {
            size_t oldSize = m_recvBuf.size();
            m_recvBuf.resize(oldSize + msgBufs[i].cbBuffer);
            memcpy(m_recvBuf.data() + oldSize, msgBufs[i].pvBuffer, msgBufs[i].cbBuffer);
        }
    }

    for (int i = 0; i < 4; i++) {
        if (msgBufs[i].BufferType == SECBUFFER_EXTRA && msgBufs[i].pvBuffer && msgBufs[i].cbBuffer > 0) {
            m_extraBuf.assign(
                reinterpret_cast<uint8_t*>(msgBufs[i].pvBuffer),
                reinterpret_cast<uint8_t*>(msgBufs[i].pvBuffer) + msgBufs[i].cbBuffer);
        }
    }

    if (m_recvBuf.empty()) return 0;

    size_t copyLen = m_recvBuf.size() < bufSize ? m_recvBuf.size() : bufSize;
    memcpy(buf, m_recvBuf.data(), copyLen);
    m_recvBuf.erase(m_recvBuf.begin(), m_recvBuf.begin() + copyLen);
    return (int)copyLen;
}

std::string SchannelTLS::wideToUtf8(const wchar_t* wstr)
{
    if (!wstr) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
    return result;
}
