#pragma once

// ============================================================================
// SchannelTLS — 基于 Windows SChannel SSPI 的 TLS 客户端封装
// ============================================================================
// 功能说明：
//   使用 Windows 内置的 SChannel 安全服务提供程序（SSP）实现 TLS 1.2 客户端。
//   提供 TCP 连接建立、TLS 握手、加密发送/解密接收等完整功能。
//
// 依赖：
//   - Windows SChannel (SSPI)
//   - Winsock 2.2
// ============================================================================

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

/**
 * @brief 基于 Windows SChannel 的 TLS 客户端类
 *
 * 封装了 SSPI（Security Support Provider Interface）的 TLS 客户端功能，
 * 通过 SChannel 安全包实现加密通信。支持：
 *   - TCP 连接建立（IPv4/IPv6）
 *   - TLS 1.2 客户端握手（支持服务器证书手动验证）
 *   - 加密数据发送（自动分块并添加 TLS 记录头/尾）
 *   - 解密数据接收（自动处理 TLS 记录解析、粘包和分包）
 *   - 安全断开连接（发送关闭通知）
 *
 * @note 该类不可拷贝（拷贝构造函数和赋值运算符被删除）
 */
class SchannelTLS {
public:
    SchannelTLS();
    ~SchannelTLS();

    // 禁止拷贝语义
    SchannelTLS(const SchannelTLS&) = delete;
    SchannelTLS& operator=(const SchannelTLS&) = delete;

    /**
     * @brief 连接到远程 TLS 服务器（TCP 连接 + TLS 握手）
     * @param host 服务器主机名或 IP 地址
     * @param port 服务器端口号
     * @throw std::runtime_error 连接或握手失败时抛出
     */
    void connect(const std::string& host, uint16_t port);

    /**
     * @brief 断开 TLS 连接（发送关闭通知并释放资源）
     */
    void disconnect();

    /**
     * @brief 发送数据（通过 TLS 加密后发送）
     * @param data 要发送的数据（字节向量）
     * @return 成功时返回发送的原始数据字节数，失败返回 -1
     */
    int send(const std::vector<uint8_t>& data);

    /**
     * @brief 发送数据（通过 TLS 加密后发送）
     * @param data 要发送的数据缓冲区指针
     * @param len  要发送的数据长度
     * @return 成功时返回发送的原始数据字节数，失败返回 -1
     */
    int send(const uint8_t* data, size_t len);

    /**
     * @brief 接收数据（接收并解密 TLS 数据）
     * @param buf       输出缓冲区（vector 形式，自动调整大小）
     * @param timeoutMs 超时时间（毫秒），默认 5000ms
     * @return 成功返回接收到的字节数，超时返回 0，失败返回 -1
     */
    int recv(std::vector<uint8_t>& buf, int timeoutMs = 5000);

    /**
     * @brief 接收数据（接收并解密 TLS 数据）
     * @param buf       输出缓冲区指针
     * @param bufSize   缓冲区大小
     * @param timeoutMs 超时时间（毫秒），默认 5000ms
     * @return 成功返回接收到的字节数，超时返回 0，失败返回 -1
     */
    int recv(uint8_t* buf, size_t bufSize, int timeoutMs = 5000);

    /**
     * @brief 检查是否已建立 TLS 连接
     * @return true 已连接，false 未连接
     */
    bool isConnected() const { return m_connected; }

    /**
     * @brief 初始化 Winsock 库
     * @throw std::runtime_error 初始化失败时抛出
     */
    static void initWinsock();

    /**
     * @brief 清理 Winsock 库
     */
    static void cleanupWinsock();

private:
    /**
     * @brief 建立底层 TCP 连接
     * @param host 目标主机名或 IP
     * @param port 目标端口
     * @throw std::runtime_error 连接失败时抛出
     */
    void tcpConnect(const std::string& host, uint16_t port);

    /**
     * @brief 执行 TLS 握手（通过 SSPI InitializeSecurityContext）
     * @param host 服务器主机名（用于 SNI 和目标名称）
     * @throw std::runtime_error 握手失败时抛出
     */
    void performHandshake(const std::string& host);

    /**
     * @brief 查询 TLS 连接的最大消息大小、头部和尾部大小
     * @return SecPkgContext_StreamSizes 结构体
     * @throw std::runtime_error 查询失败时抛出
     */
    SecPkgContext_StreamSizes queryStreamSizes();

    /**
     * @brief 将宽字符字符串转换为 UTF-8 编码
     * @param wstr 宽字符字符串指针
     * @return UTF-8 编码的 std::string
     */
    static std::string wideToUtf8(const wchar_t* wstr);

    // ---- SSPI 安全凭证和上下文句柄 ----
    CredHandle  m_hCred;        ///< SSPI 凭证句柄（由 AcquireCredentialsHandle 获得）
    CtxtHandle  m_hContext;     ///< SSPI 安全上下文句柄（由 InitializeSecurityContext 获得）

    // ---- 套接字和连接状态 ----
    SOCKET      m_socket;       ///< TCP 套接字句柄
    bool        m_connected;    ///< 是否已建立 TLS 连接
    bool        m_contextValid; ///< SSPI 安全上下文是否有效

    // ---- TLS 流信息 ----
    SecPkgContext_StreamSizes m_streamSizes; ///< TLS 流大小信息（头部、尾部、最大消息等）
    bool m_streamSizesQueried;               ///< 是否已成功查询流大小信息

    // ---- 接收缓冲 ----
    std::vector<uint8_t> m_recvBuf;  ///< 解密后的应用数据缓冲区（处理粘包）
    std::vector<uint8_t> m_extraBuf; ///< DecryptMessage 产生的额外数据（跨帧数据）
};

