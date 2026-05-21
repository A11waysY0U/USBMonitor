#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// 可移植的主机 <-> 网络字节序转换（始终为大端序）
// ---------------------------------------------------------------------------
inline uint32_t hton32(uint32_t host) {
#ifdef _MSC_VER
    return _byteswap_ulong(host);
#else
    return __builtin_bswap32(host);
#endif
}
inline uint32_t ntoh32(uint32_t net) { return hton32(net); }

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------
static const uint16_t PROTOCOL_PORT = 9443;

enum class MessageType : uint32_t {
    HEARTBEAT = 0x0001,
    DATA      = 0x0002,
    COMMAND   = 0x0003,
    RESPONSE  = 0x0004,
};

// ---------------------------------------------------------------------------
// 消息头（打包，8字节）
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct MessageHeader {
    uint32_t type;
    uint32_t length;

    void toNetwork() {
        type   = hton32(type);
        length = hton32(length);
    }
    void toHost() {
        type   = ntoh32(type);
        length = ntoh32(length);
    }
};
#pragma pack(pop)

static const size_t HEADER_SIZE      = sizeof(MessageHeader);
static const size_t MAX_PAYLOAD_SIZE = 1024 * 1024;

// ---------------------------------------------------------------------------
// 纯协议辅助函数（不依赖传输层）
// ---------------------------------------------------------------------------

/// 将网络字节序的头部写入 @p dst（至少需要 HEADER_SIZE 字节）。
inline size_t packHeader(uint8_t* dst, MessageType type, uint32_t payloadLen) {
    MessageHeader hdr;
    hdr.type   = static_cast<uint32_t>(type);
    hdr.length = payloadLen;
    hdr.toNetwork();
    std::memcpy(dst, &hdr, HEADER_SIZE);
    return HEADER_SIZE;
}

/// 将完整消息（头部 + 负载）序列化为字节向量。
std::vector<uint8_t> packMessage(MessageType type, const std::vector<uint8_t>& payload);
