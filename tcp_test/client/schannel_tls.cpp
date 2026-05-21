// ============================================================================
// SchannelTLS — 基于 Windows SChannel SSPI 的 TLS 客户端实现
// ============================================================================
//
// 本文件实现了 SchannelTLS 类的所有方法，包括：
//   - TCP 连接管理（建立与断开）
//   - TLS 1.2 握手流程（通过 SSPI InitializeSecurityContext）
//   - 加密数据发送（自动分块 + TLS 记录封装）
//   - 解密数据接收（自动处理粘包、分包、不完整消息）
//   使用 Windows 内置的 SChannel 安全包，无需外部 OpenSSL 等依赖。
// ============================================================================

#include "schannel_tls.hpp"
#include <cstdio>

// ============================================================================
// 构造函数
// ============================================================================
SchannelTLS::SchannelTLS()
    : m_socket(INVALID_SOCKET)          // 初始化为无效套接字
    , m_connected(false)                // 尚未建立连接
    , m_contextValid(false)             // SSPI 上下文尚未初始化
    , m_streamSizesQueried(false)       // 流大小尚未查询
{
    // 将 SSPI 凭证句柄和上下文句柄标记为无效
    SecInvalidateHandle(&m_hCred);
    SecInvalidateHandle(&m_hContext);
    // 清零流大小结构体
    memset(&m_streamSizes, 0, sizeof(m_streamSizes));
}

// ============================================================================
// 析构函数 — 确保资源释放
// ============================================================================
SchannelTLS::~SchannelTLS()
{
    disconnect();
}

// ============================================================================
// 静态方法: 初始化 Winsock 库
// ============================================================================
// 在使用任何 Winsock 函数之前必须先调用此函数。
// 请求 Winsock 2.2 版本。
// ============================================================================
void SchannelTLS::initWinsock()
{
    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        throw std::runtime_error("WSAStartup 失败: " + std::to_string(ret));
    }
}

// ============================================================================
// 静态方法: 清理 Winsock 库
// ============================================================================
void SchannelTLS::cleanupWinsock()
{
    WSACleanup();
}

// ============================================================================
// 私有方法: 建立 TCP 连接
// ============================================================================
// 使用 getaddrinfo 解析主机名（支持 IPv4 和 IPv6），
// 遍历所有可用地址直到成功建立连接。
//
// @param host  目标主机名或 IP 地址
// @param port  目标端口号
// @throw std::runtime_error 解析失败或所有地址连接失败时抛出
// ============================================================================
void SchannelTLS::tcpConnect(const std::string& host, uint16_t port)
{
    // --- 1. 地址解析 ---
    struct addrinfo hints, *result = nullptr, *ptr = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;      // 支持 IPv4 和 IPv6
    hints.ai_socktype = SOCK_STREAM;    // TCP 流式套接字
    hints.ai_protocol = IPPROTO_TCP;    // TCP 协议

    std::string portStr = std::to_string(port);
    int ret = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
    if (ret != 0) {
        throw std::runtime_error("getaddrinfo 失败: " + std::to_string(ret));
    }

    // --- 2. 遍历地址链表，尝试连接 ---
    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        // 创建套接字
        m_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (m_socket == INVALID_SOCKET) continue;  // 创建失败，尝试下一个地址

        // 尝试连接
        if (::connect(m_socket, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
            break;  // 连接成功，退出循环
        }

        // 连接失败，关闭套接字继续尝试
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }

    // 释放地址信息链表
    freeaddrinfo(result);

    // --- 3. 检查连接结果 ---
    if (m_socket == INVALID_SOCKET) {
        throw std::runtime_error("连接到 " + host + ":" + portStr + " 失败");
    }
}

// ============================================================================
// 公有方法: 连接到 TLS 服务器
// ============================================================================
// 完整流程: TCP 连接建立 -> TLS 握手
// ============================================================================
void SchannelTLS::connect(const std::string& host, uint16_t port)
{
    // 步骤1: 建立底层 TCP 连接
    tcpConnect(host, port);
    // 步骤2: 执行 TLS 握手
    performHandshake(host);
    m_connected = true;
}

// ============================================================================
// 私有方法: 执行 TLS 1.2 握手
// ============================================================================
// 通过 SSPI InitializeSecurityContext 实现 TLS 客户端握手。
// 这是一个多轮次（loop）的握手过程：
//   - 第一轮: 生成 ClientHello，发送给服务器
//   - 后续轮次: 处理 ServerHello/证书/ServerKeyExchange 等，
//               发送 ClientKeyExchange/ChangeCipherSpec/Finished
//   直到返回 SEC_E_OK 表示握手完成。
//
// 注意: 本实现使用 SCH_CRED_MANUAL_CRED_VALIDATION，
//       不自动验证服务器证书，需要调用者手动验证。
//
// @param host  服务器主机名（用于 SNI 和目标名称）
// @throw std::runtime_error 任一握手步骤失败时抛出
// ============================================================================
void SchannelTLS::performHandshake(const std::string& host)
{
    // ---- 1. 准备 SChannel 凭证 ----
    SCHANNEL_CRED cred = {};
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;  // 仅启用 TLS 1.2
    cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION        // 手动验证服务器证书
                 | SCH_CRED_NO_DEFAULT_CREDS              // 不提供客户端证书
                 | SCH_CRED_NO_SERVERNAME_CHECK;          // 不检查证书中的主机名

    SecInvalidateHandle(&m_hCred);

    // ---- 2. 获取 SSPI 凭证句柄 ----
    TimeStamp tsExpiry;
    SECURITY_STATUS secStatus = AcquireCredentialsHandleW(
        nullptr,                        // 使用当前进程的登录凭证
        const_cast<LPWSTR>(UNISP_NAME), // 使用 UNISP（SChannel）安全包
        SECPKG_CRED_OUTBOUND,           // 出站方向（客户端）
        nullptr,                        // 不使用认证标识
        &cred,                          // SChannel 凭证
        nullptr,                        // 不使用 GetKey 函数
        nullptr,                        // 无额外参数
        &m_hCred,                       // [输出] 凭证句柄
        &tsExpiry                       // [输出] 过期时间
    );

    if (secStatus != SEC_E_OK) {
        throw std::runtime_error("AcquireCredentialsHandle 失败: 0x"
            + std::to_string(secStatus));
    }

    // ---- 3. 准备 TLS 握手循环 ----
    SecInvalidateHandle(&m_hContext);

    // 输出缓冲区：存放需要发送给服务器的握手数据
    SecBufferDesc outBufDesc;
    SecBuffer     outSecBuf;
    DWORD         dwSSPIOutFlags = 0;
    // 输入标志：请求序列检测、重放检测、机密性、流模式等
    DWORD         dwSSPIInFlags =
        ISC_REQ_SEQUENCE_DETECT   |    // 检测乱序消息
        ISC_REQ_REPLAY_DETECT     |    // 检测重放攻击
        ISC_REQ_CONFIDENTIALITY   |    // 请求加密
        ISC_RET_EXTENDED_ERROR    |    // 返回扩展错误信息
        ISC_REQ_ALLOCATE_MEMORY   |    // 让 SSPI 分配内存
        ISC_REQ_STREAM;                 // 流式 TLS（TLS 记录协议）

    outBufDesc.ulVersion = SECBUFFER_VERSION;
    outBufDesc.cBuffers  = 1;
    outBufDesc.pBuffers  = &outSecBuf;

    outSecBuf.BufferType = SECBUFFER_TOKEN;    // 安全令牌（握手数据）
    outSecBuf.pvBuffer   = nullptr;
    outSecBuf.cbBuffer   = 0;

    // 输入缓冲区：存放从服务器收到的握手响应
    SecBufferDesc inBufDesc;
    SecBuffer     inSecBufs[2];
    bool          firstLoop = true;     // 是否是第一轮（初始 ClientHello）
    bool          done      = false;    // 握手是否完成

    // 将主机名转为宽字符串（SSPI 需要宽字符）
    std::wstring targetName(host.begin(), host.end());

    // ---- 4. TLS 握手循环 ----
    while (!done) {
        // 调用 InitializeSecurityContext 处理握手
        // 第一轮: 无输入（生成 ClientHello）
        // 后续轮次: 输入服务器发来的握手响应消息
        secStatus = InitializeSecurityContextW(
            &m_hCred,
            firstLoop ? nullptr : &m_hContext,   // 第一轮无旧上下文
            const_cast<SEC_WCHAR*>(reinterpret_cast<const SEC_WCHAR*>(targetName.c_str())),
            dwSSPIInFlags,
            0,                                     // 保留参数
            SECURITY_NATIVE_DREP,                  // 本地字节序
            firstLoop ? nullptr : &inBufDesc,      // 第一轮无输入
            0,                                     // 保留参数
            &m_hContext,                           // [输出] 安全上下文
            &outBufDesc,                           // [输出] 待发送的握手数据
            &dwSSPIOutFlags,                       // [输出] 输出标志
            &tsExpiry                              // [输出] 过期时间
        );

        // 如果 SSPI 要求调用 CompleteAuthToken，则调用
        if (secStatus == SEC_I_COMPLETE_NEEDED || secStatus == SEC_I_COMPLETE_AND_CONTINUE) {
            CompleteAuthToken(&m_hContext, &outBufDesc);
        }

        // 第一轮循环：标记上下文有效
        if (firstLoop) {
            m_contextValid = true;
        }

        // ---- 5. 发送握手数据（ClientHello 等）给服务器 ----
        if (outSecBuf.cbBuffer > 0 && outSecBuf.pvBuffer != nullptr) {
            int sent = ::send(m_socket,
                reinterpret_cast<const char*>(outSecBuf.pvBuffer),
                (int)outSecBuf.cbBuffer, 0);
            if (sent <= 0) {
                FreeContextBuffer(outSecBuf.pvBuffer);
                throw std::runtime_error("握手发送失败");
            }
            // 释放 SSPI 分配的内存
            FreeContextBuffer(outSecBuf.pvBuffer);
            outSecBuf.pvBuffer = nullptr;
        }

        // ---- 6. 检查握手状态 ----
        if (secStatus == SEC_E_OK) {
            // 握手成功完成
            done = true;
        }
        else if (secStatus == SEC_I_CONTINUE_NEEDED) {
            // 需要继续握手：从服务器接收响应
            uint8_t recvBuf[16384];
            int recvd = ::recv(m_socket, reinterpret_cast<char*>(recvBuf), sizeof(recvBuf), 0);
            if (recvd <= 0) {
                throw std::runtime_error("握手接收失败");
            }

            // 将服务器响应设置为下一次 InitializeSecurityContext 的输入
            inBufDesc.ulVersion = SECBUFFER_VERSION;
            inBufDesc.cBuffers  = 2;
            inBufDesc.pBuffers  = inSecBufs;

            inSecBufs[0].BufferType = SECBUFFER_TOKEN;   // 服务器的握手令牌
            inSecBufs[0].pvBuffer   = recvBuf;
            inSecBufs[0].cbBuffer   = (ULONG)recvd;

            inSecBufs[1].BufferType = SECBUFFER_EMPTY;    // 结束标记

            firstLoop = false;  // 不再是第一轮
        }
        else {
            // 发生了不应发生的状态
            throw std::runtime_error("InitializeSecurityContext 意外状态: 0x"
                + std::to_string(secStatus));
        }
    }

    // ---- 7. 握手完成，查询流大小参数 ----
    queryStreamSizes();
}

// ============================================================================
// 私有方法: 查询 TLS 流大小参数
// ============================================================================
// 获取当前 TLS 连接的以下参数，用于后续的加密/解密操作：
//   - cbHeader:   TLS 记录头部大小
//   - cbTrailer:  TLS 记录尾部（MAC/填充）大小
//   - cbMaximumMessage: 每个 TLS 记录能承载的最大明文数据量
//
// @return SecPkgContext_StreamSizes 结构体
// @throw std::runtime_error 查询失败时抛出
// ============================================================================
SecPkgContext_StreamSizes SchannelTLS::queryStreamSizes()
{
    SecPkgContext_StreamSizes sizes = {};
    SECURITY_STATUS secStatus = QueryContextAttributesW(
        &m_hContext, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (secStatus != SEC_E_OK) {
        throw std::runtime_error("QueryContextAttributes(StreamSizes) 失败: 0x"
            + std::to_string(secStatus));
    }
    m_streamSizes = sizes;
    m_streamSizesQueried = true;
    return sizes;
}

// ============================================================================
// 公有方法: 断开 TLS 连接
// ============================================================================
// 按顺序执行以下清理操作：
//   1. 发送 TLS 关闭通知（通过 ApplyControlToken + InitializeSecurityContext）
//   2. 删除 SSPI 安全上下文
//   3. 释放 SSPI 凭证句柄
//   4. 关闭 TCP 套接字
// ============================================================================
void SchannelTLS::disconnect()
{
    // 如果未连接，直接返回
    if (!m_connected) return;
    m_connected = false;

    // 清空缓冲区
    m_recvBuf.clear();
    m_extraBuf.clear();

    // ---- 1. 发送 TLS 关闭通知 ----
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

        // 第一步：应用关闭控制令牌
        SECURITY_STATUS secStatus = ApplyControlToken(&m_hContext, &outBufDesc);
        (void)secStatus;
        // 第二步：生成关闭通知消息
        secStatus = InitializeSecurityContextW(
            &m_hCred,
            &m_hContext,
            nullptr,            // 关闭时不需要目标名称
            dwFlags,
            0,
            SECURITY_NATIVE_DREP,
            nullptr,            // 关闭时不需要输入
            0,
            &m_hContext,
            &outBufDesc,
            &dwFlags,
            &ts
        );

        // 将关闭通知发送给服务器
        if (outSecBuf.cbBuffer > 0 && outSecBuf.pvBuffer != nullptr) {
            ::send(m_socket,
                reinterpret_cast<const char*>(outSecBuf.pvBuffer),
                (int)outSecBuf.cbBuffer, 0);
            FreeContextBuffer(outSecBuf.pvBuffer);
        }

        // 删除安全上下文
        DeleteSecurityContext(&m_hContext);
        SecInvalidateHandle(&m_hContext);
        m_contextValid = false;
    }

    // ---- 2. 释放凭证句柄 ----
    if (SecIsValidHandle(&m_hCred)) {
        FreeCredentialsHandle(&m_hCred);
        SecInvalidateHandle(&m_hCred);
    }

    // ---- 3. 关闭 TCP 套接字 ----
    if (m_socket != INVALID_SOCKET) {
        shutdown(m_socket, SD_BOTH);   // 禁止收发
        closesocket(m_socket);          // 关闭套接字
        m_socket = INVALID_SOCKET;
    }
}

// ============================================================================
// 公有方法: 发送数据（vector 重载）
// ============================================================================
// 将 vector<uint8_t> 中的数据通过 TLS 加密后发送
// ============================================================================
int SchannelTLS::send(const std::vector<uint8_t>& data)
{
    return send(data.data(), data.size());
}

// ============================================================================
// 公有方法: 发送数据（核心实现）
// ============================================================================
// 流程：
//   1. 将数据按 cbMaximumMessage 分块
//   2. 对每块数据调用 EncryptMessage 加密（添加 TLS 头部和尾部）
//   3. 通过 TCP 套接字发送加密后的数据
//
// 注意：发送的是 TLS 记录（头部+加密数据+尾部），不是原始明文。
//
// @param data 明文数据缓冲区
// @param len  明文数据长度
// @return 成功返回已发送的原始（明文）字节数，失败返回 -1
// ============================================================================
int SchannelTLS::send(const uint8_t* data, size_t len)
{
    // 检查连接状态和流大小信息是否可用
    if (!m_connected || !m_streamSizesQueried) return -1;

    size_t headerSize  = m_streamSizes.cbHeader;      // TLS 记录头部大小
    size_t trailerSize = m_streamSizes.cbTrailer;     // TLS 记录尾部（MAC+填充）大小
    size_t maxChunk    = m_streamSizes.cbMaximumMessage; // 每个记录的最大明文数据量

    if (maxChunk == 0) return -1;

    int totalSent = 0;    // 累计已发送的原始字节数
    size_t pos = 0;       // 当前处理位置

    // ---- 分块发送循环 ----
    while (pos < len) {
        // 计算本次块大小（不能超过 TLS 记录的最大消息限制）
        size_t chunkSize = len - pos;
        if (chunkSize > maxChunk) chunkSize = maxChunk;

        // 分配缓冲区：头部 + 明文数据 + 尾部
        std::vector<uint8_t> sendBuf(headerSize + chunkSize + trailerSize);

        // 设置 SSPI SecBuffer 描述符
        // 使用 4 缓冲区模型：
        //   [0] = 流头部（TLS 记录头）
        //   [1] = 数据（明文）
        //   [2] = 流尾部（MAC + 填充）
        //   [3] = 保留（空）
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

        // 加密：EncryptMessage 会填充 TLS 头部和尾部（MAC + 填充）
        SECURITY_STATUS secStatus = EncryptMessage(&m_hContext, 0, &msgDesc, 0);
        if (secStatus != SEC_E_OK) {
            return -1;
        }

        // 发送加密后的 TLS 记录（可能包含部分填充数据）
        // 实际发送大小由 SSPI 更新后的 cbBuffer 决定
        int actualSendSize = (int)(msgBufs[0].cbBuffer + msgBufs[1].cbBuffer + msgBufs[2].cbBuffer);
        int toSend = actualSendSize;
        int sentTotal = 0;
        while (sentTotal < toSend) {
            int sent = ::send(m_socket,
                reinterpret_cast<const char*>(sendBuf.data()) + sentTotal,
                toSend - sentTotal, 0);
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

// ============================================================================
// 公有方法: 接收数据（vector 重载）
// ============================================================================
// 接收 TLS 解密后的数据，以 vector<uint8_t> 形式返回。
// 自动调整 vector 大小以匹配实际接收到的数据量。
// ============================================================================
int SchannelTLS::recv(std::vector<uint8_t>& buf, int timeoutMs)
{
    buf.resize(65536);
    int ret = recv(buf.data(), buf.size(), timeoutMs);
    if (ret > 0) {
        buf.resize(ret);       // 调整到实际接收的字节数
    } else {
        buf.clear();           // 失败或超时，清空缓冲区
    }
    return ret;
}

// ============================================================================
// 公有方法: 接收数据（核心实现）
// ============================================================================
// 该函数处理了 TLS 接收的多个复杂场景：
//
// 1. **粘包处理**（m_recvBuf）：
//    如果一次解密得到多个 TLS 记录的应用数据，多余的会暂存到 m_recvBuf，
//    下次调用时优先从 m_recvBuf 取出。
//
// 2. **跨帧数据**（m_extraBuf）：
//    如果 TCP 数据流中包含下一个 TLS 记录的部分数据（SECBUFFER_EXTRA），
//    会暂存到 m_extraBuf，下次接收时先从此处读取。
//
// 3. **不完整消息处理**（SEC_E_INCOMPLETE_MESSAGE）：
//    当收到的 TCP 数据不足以构成一个完整的 TLS 记录时，自动循环 recv
//    直到数据足够解密。
//
// 4. **超时支持**：
//    通过 select() 实现可选的接收超时。
//
// @param buf       输出缓冲区
// @param bufSize   缓冲区大小
// @param timeoutMs 超时时间（毫秒），≤0 表示阻塞
// @return 成功返回接收到的明文字节数，超时返回 0，失败返回 -1
// ============================================================================
int SchannelTLS::recv(uint8_t* buf, size_t bufSize, int timeoutMs)
{
    if (!m_connected) return -1;

    // ---- 1. 优先从接收缓冲区取出数据（处理粘包） ----
    if (!m_recvBuf.empty()) {
        size_t copyLen = m_recvBuf.size() < bufSize ? m_recvBuf.size() : bufSize;
        memcpy(buf, m_recvBuf.data(), copyLen);
        m_recvBuf.erase(m_recvBuf.begin(), m_recvBuf.begin() + copyLen);
        return (int)copyLen;
    }

    // ---- 2. 设置 select 超时 ----
    if (timeoutMs > 0) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_socket, &fds);

        struct timeval tv;
        tv.tv_sec  = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        int selRet = select(0, &fds, nullptr, nullptr, &tv);
        if (selRet <= 0) return selRet;  // 超时或出错返回
    }

    // ---- 3. 收集原始 TCP 数据 ----
    uint8_t rawBuf[65536];
    int rawLen = 0;

    // 如果上次有跨帧剩余数据，先放入 rawBuf
    if (!m_extraBuf.empty()) {
        rawLen = (int)(m_extraBuf.size() < sizeof(rawBuf) ? m_extraBuf.size() : sizeof(rawBuf));
        memcpy(rawBuf, m_extraBuf.data(), rawLen);
        m_extraBuf.erase(m_extraBuf.begin(), m_extraBuf.begin() + rawLen);
    }

    // 从套接字接收更多数据
    int more = ::recv(m_socket, reinterpret_cast<char*>(rawBuf) + rawLen,
                      (int)(sizeof(rawBuf) - rawLen), 0);
    if (more < 0) return -1;
    if (more == 0 && rawLen == 0) return 0;  // 连接关闭且无旧数据
    rawLen += more;

    // ---- 4. 配置 SecBuffer 描述符用于解密 ----
    // 使用 4 缓冲区模型（SSPI 流解密协议）：
    //   [0] = 输入加密数据（SECBUFFER_DATA）
    //   [1-3] = 初始为空，DecryptMessage 会更新它们的类型
    //     解密后:
    //       [0] 或某个缓冲区变为 SECBUFFER_DATA = 解密后的明文
    //       某个缓冲区变为 SECBUFFER_EXTRA = 属于下一个 TLS 记录的额外数据
    // 其他缓冲区变为 SECBUFFER_STREAM_HEADER / SECBUFFER_STREAM_TRAILER
    // ========================================================================
    SecBufferDesc msgDesc;
    SecBuffer     msgBufs[4];

    msgDesc.ulVersion = SECBUFFER_VERSION;
    msgDesc.cBuffers  = 4;
    msgDesc.pBuffers  = msgBufs;

    msgBufs[0].BufferType = SECBUFFER_DATA;    // 输入：加密的 TLS 记录
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

    // ---- 5. 处理不完整消息 ----
    // 如果收到的数据不足以构成一个完整的 TLS 记录，继续接收直到数据够用
    while (secStatus == SEC_E_INCOMPLETE_MESSAGE) {
        int more = ::recv(m_socket,
            reinterpret_cast<char*>(rawBuf) + rawLen,
            (int)(sizeof(rawBuf) - rawLen), 0);
        if (more <= 0) return -1;

        rawLen += more;

        // 重置缓冲区描述符（仅更新数据和长度）
        msgBufs[0].cbBuffer = (ULONG)rawLen;
        msgBufs[1].BufferType = SECBUFFER_EMPTY;
        msgBufs[2].BufferType = SECBUFFER_EMPTY;
        msgBufs[3].BufferType = SECBUFFER_EMPTY;

        secStatus = DecryptMessage(&m_hContext, &msgDesc, 0, nullptr);
    }

    if (secStatus != SEC_E_OK) {
        return -1;
    }

    // ---- 6. 提取解密后的应用数据 ----
    for (int i = 0; i < 4; i++) {
        if (msgBufs[i].BufferType == SECBUFFER_DATA && msgBufs[i].pvBuffer && msgBufs[i].cbBuffer > 0) {
            // 将解密后的数据追加到接收缓冲区
            size_t oldSize = m_recvBuf.size();
            m_recvBuf.resize(oldSize + msgBufs[i].cbBuffer);
            memcpy(m_recvBuf.data() + oldSize, msgBufs[i].pvBuffer, msgBufs[i].cbBuffer);
        }
    }

    // ---- 7. 保存跨帧的额外数据 ----
    // 如果解密一个 TLS 记录后，TCP 流中还有下一个 TLS 记录的部分数据，
    // SSPI 会将其标记为 SECBUFFER_EXTRA，我们需要保存供下次使用。
    for (int i = 0; i < 4; i++) {
        if (msgBufs[i].BufferType == SECBUFFER_EXTRA && msgBufs[i].pvBuffer && msgBufs[i].cbBuffer > 0) {
            m_extraBuf.assign(
                reinterpret_cast<uint8_t*>(msgBufs[i].pvBuffer),
                reinterpret_cast<uint8_t*>(msgBufs[i].pvBuffer) + msgBufs[i].cbBuffer);
        }
    }

    // 如果没有解密出数据，返回 0
    if (m_recvBuf.empty()) return 0;

    // ---- 8. 从接收缓冲区拷贝到用户缓冲区 ----
    size_t copyLen = m_recvBuf.size() < bufSize ? m_recvBuf.size() : bufSize;
    memcpy(buf, m_recvBuf.data(), copyLen);
    m_recvBuf.erase(m_recvBuf.begin(), m_recvBuf.begin() + copyLen);
    return (int)copyLen;
}

// ============================================================================
// 私有静态方法: 宽字符字符串转 UTF-8
// ============================================================================
// 使用 Windows API WideCharToMultiByte 将 wchar_t* 转换为 UTF-8 编码的
// std::string。如果输入为 nullptr，返回空字符串。
//
// @param wstr 输入的宽字符字符串
// @return UTF-8 编码的 std::string
// ============================================================================
std::string SchannelTLS::wideToUtf8(const wchar_t* wstr)
{
    if (!wstr) return {};
    // 第一次调用获取需要的 UTF-8 缓冲区长度（含 null 终止符）
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    // 第二次调用实际转换（去掉 null 终止符）
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
    return result;
}
