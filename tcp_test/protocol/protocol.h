#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// Portable host <-> network byte order (always big-endian)
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
// Protocol constants
// ---------------------------------------------------------------------------
static const uint16_t PROTOCOL_PORT = 9443;

enum class MessageType : uint32_t {
    HEARTBEAT = 0x0001,
    DATA      = 0x0002,
    COMMAND   = 0x0003,
    RESPONSE  = 0x0004,
};

// ---------------------------------------------------------------------------
// Message header (packed, 8 bytes)
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
// Pure protocol helpers (no transport dependency)
// ---------------------------------------------------------------------------

/// Write a network-byte-order header into @p dst (must be at least HEADER_SIZE bytes).
inline size_t packHeader(uint8_t* dst, MessageType type, uint32_t payloadLen) {
    MessageHeader hdr;
    hdr.type   = static_cast<uint32_t>(type);
    hdr.length = payloadLen;
    hdr.toNetwork();
    std::memcpy(dst, &hdr, HEADER_SIZE);
    return HEADER_SIZE;
}

/// Serialise a complete message (header + payload) into a byte vector.
std::vector<uint8_t> packMessage(MessageType type, const std::vector<uint8_t>& payload);
