#include "protocol.h"
#include <vector>
#include <cstdint>
#include <cstring>

std::vector<uint8_t> packMessage(MessageType type, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> result(HEADER_SIZE + payload.size());
    packHeader(result.data(), type, static_cast<uint32_t>(payload.size()));
    if (!payload.empty()) {
        std::memcpy(result.data() + HEADER_SIZE, payload.data(), payload.size());
    }
    return result;
}
