#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <emscripten/bind.h>

std::string to_hex_string(const unsigned char* bytes, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    // SHA256_Update(&sha256, input.c_str(), input.size());
    // SHA256_Final(hash, &sha256);
    // return to_hex_string(hash, SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    return to_hex_string(hash, SHA256_DIGEST_LENGTH);
}

// Function to generate a 2048-bit RSA key pair
emscripten::val generateRsaKeyPair() {
    EVP_PKEY *pkey = EVP_PKEY_new();
    // Note: In a real app, you'd use RSA_generate_key_ex for more options, 
    // but this is simpler for a basic example.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        // Handle error
        return emscripten::val::null();
    }
    
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Write private key to a memory buffer
    BIO *bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS8PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL);
    char *private_key_pem;
    long private_len = BIO_get_mem_data(bio_private, &private_key_pem);
    std::string private_key_str(private_key_pem, private_len);
    BIO_free_all(bio_private);

    // Write public key to a memory buffer
    BIO *bio_public = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_public, pkey);
    char *public_key_pem;
    long public_len = BIO_get_mem_data(bio_public, &public_key_pem);
    std::string public_key_str(public_key_pem, public_len);
    BIO_free_all(bio_public);

    EVP_PKEY_free(pkey);

    // Return keys as a JavaScript object
    emscripten::val result = emscripten::val::object();
    result.set("privateKey", private_key_str);
    result.set("publicKey", public_key_str);

    return result;
}

EMSCRIPTEN_BINDINGS(crypto_module) {
    emscripten::function("sha256", &sha256 /*emscripten::allow_raw_pointers() */);
    emscripten::function("generateRsaKeyPair", &generateRsaKeyPair);
    // emscripten::register_vector<std::string>("StringVector");
    // emscripten::register_vector<unsigned char>("ByteVector");
}