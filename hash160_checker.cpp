#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <secp256k1.h>
#include <openssl/evp.h>
#include <cstdint>
#include <atomic>
#include <thread>
#include <chrono>

// Função para converter uint64_t para string hexadecimal
std::string to_hex(uint64_t value) {
    std::ostringstream stream;
    stream << std::hex << std::setw(16) << std::setfill('0') << value;
    return stream.str();
}

// Função para calcular o Hash160 (SHA-256 seguido de RIPEMD-160)
void hash160(const unsigned char *data, size_t len, unsigned char *out) {
    unsigned char sha_out[32];

    // SHA-256 usando EVP
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, sha_out, NULL);
    EVP_MD_CTX_free(ctx);

    // RIPEMD-160 usando EVP
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(ctx, sha_out, 32);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

void process_range(uint64_t start_range, uint64_t end_range, const std::string &target_hash, 
                   std::atomic<bool> &found, uint64_t &result_key, std::atomic<uint64_t> &keys_checked) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char pubkey[33]; // Chave pública comprimida
    unsigned char hash_out[20];

    for (uint64_t priv_key = start_range; priv_key <= end_range; ++priv_key) {
        if (found.load()) break; // Encerrar se encontrado em outra thread

        unsigned char priv_key_bytes[32] = {0};
        for (int i = 0; i < 8; ++i) {
            priv_key_bytes[31 - i] = (priv_key >> (8 * i)) & 0xFF;
        }

        // Gerar chave pública
        secp256k1_pubkey pubkey_raw;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey_raw, priv_key_bytes)) {
            continue;
        }

        // Serializar a chave pública
        size_t pubkey_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &pubkey_raw, SECP256K1_EC_COMPRESSED);

        // Calcular o Hash160
        hash160(pubkey, pubkey_len, hash_out);

        // Comparar com o alvo
        std::ostringstream hash_hex;
        for (int i = 0; i < 20; ++i) {
            hash_hex << std::hex << std::setw(2) << std::setfill('0') << (int)hash_out[i];
        }
        if (hash_hex.str() == target_hash) {
            found.store(true);
            result_key = priv_key;
            break;
        }
        keys_checked.fetch_add(1, std::memory_order_relaxed);
    }

    secp256k1_context_destroy(ctx);
}

int main() {
    uint64_t start_range = 0x40000000000000000;
    uint64_t end_range = 0xffffffffffffffff;
    const std::string target_hash = "739437bb3dd6d1983e66629c5f08c70e52769371";

    std::atomic<bool> found(false);
    std::atomic<uint64_t> keys_checked(0);
    uint64_t result_key = 0;

    unsigned int num_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;

    uint64_t total_keys = end_range - start_range + 1;
    uint64_t range_per_thread = total_keys / num_threads;

    auto start_time = std::chrono::steady_clock::now();

    for (unsigned int i = 0; i < num_threads; ++i) {
        uint64_t start = start_range + i * range_per_thread;
        uint64_t end = (i == num_threads - 1) ? end_range : (start + range_per_thread - 1);
        threads.emplace_back(process_range, start, end, std::ref(target_hash), std::ref(found), std::ref(result_key), std::ref(keys_checked));
    }

    while (!found.load() && keys_checked.load() < total_keys) {
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();

        double progress = (double)keys_checked / total_keys * 100.0;
        double keys_per_second = elapsed_time > 0 ? keys_checked / (double)elapsed_time : 0;
        double estimated_time = keys_per_second > 0 ? (total_keys - keys_checked) / keys_per_second : 0;

        std::cout << "Progresso: " << std::fixed << std::setprecision(2) << progress << "% (" 
                  << keys_checked << "/" << total_keys << " chaves verificadas), "
                  << "Velocidade: " << (int)keys_per_second << " chaves/s, "
                  << "Tempo restante: " << (int)(estimated_time / 60) << " min "
                  << (int)((int)estimated_time % 60) << " s" << std::flush;

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    for (auto &t : threads) {
        t.join();
    }

    if (found.load()) {
        std::cout << "Chave privada encontrada: 0x";
        for (int i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << ((result_key >> (8 * (31 - i))) & 0xFF);
        }
        std::cout << std::endl;
    } else {
        std::cout << "Nenhuma chave encontrada no intervalo." << std::endl;
    }

    return 0;
}
