#pragma once

#include <string>
#include <string_view>

#include <tao/json.hpp>


namespace banyan {


std::string randomBytes(size_t n);

std::string hmacSha256(std::string_view key, std::string_view msg);

std::string base64Encode(std::string_view in);
std::string base64Decode(std::string_view in); // throws

struct KeyPair {
    std::string secretKey; // 32 bytes
    std::string pubkey;    // 32 bytes, x-only

    static KeyPair generate();
    static KeyPair fromSecret(std::string_view secretKey); // throws

    tao::json::value sign(uint64_t kind, tao::json::value tags, std::string content, uint64_t createdAt = 0) const;
};

// NIP-44 v2
std::string nip44ConversationKey(std::string_view secretKey, std::string_view pubkey);
std::string nip44Encrypt(std::string_view plaintext, std::string_view conversationKey);
std::string nip44Decrypt(std::string_view payload, std::string_view conversationKey); // throws


}
