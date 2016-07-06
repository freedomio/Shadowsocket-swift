#include <sys/socket.h>
#include <openssl/rand.h>
#include <strings.h>
#include <openssl/md5.h>
#include "sodium.h"
#include "local.h"
#include "table.h"
#include "encrypt.h"
#include <secure/_string.h>


#define CIPHER_TABLE 0
#define CIPHER_OPENSSL 1
#define CIPHER_SODIUM 2
static uint8_t cipher;

#define SODIUM_BLOCK_SIZE 64

static unsigned char sodium_buf[BUF_SIZE + SODIUM_BLOCK_SIZE + 16];

size_t encryption_iv_len[] = {
        0,
        16,
        8,
        8,
        16,
        16,
        16,
        8,
        8,
        8,
        8,
        0,
        16
};

const char *shadowsocks_encryption_names[] = {
        "table",
        "rc4-md5",
        "salsa20",
        "chacha20",
        "aes-256-cfb",
        "aes-192-cfb",
        "aes-128-cfb",
        "bf-cfb",
        "cast5-cfb",
        "des-cfb",
        "rc2-cfb",
        "rc4",
        "seed-cfb"
};

#define ENCRYPTION_TABLE 0
#define ENCRYPTION_RC4_MD5 1
#define ENCRYPTION_SALSA20 2
#define ENCRYPTION_CHACHA20 3

static int _method;
static int _key_len;
static const EVP_CIPHER *_cipher;
static unsigned char _key[EVP_MAX_KEY_LENGTH];
unsigned char *shadowsocks_key;

void init_cipher(struct encryption_ctx *ctx, const unsigned char *iv, size_t iv_len, int is_cipher);
//初始化method
int encryption_method_from_string(const char *name) {
    // TODO use an O(1) way
    for (int i = 0; i < kShadowsocksMethods; i++) {
        if (strcasecmp(name, shadowsocks_encryption_names[i]) == 0) {
            return i;
        }
    }
    return 0;
}

//重新加密函数
void cipher_update(struct encryption_ctx *ctx, unsigned char *out, size_t *outlen, unsigned char *in, size_t inlen) {
    if (ctx->cipher == CIPHER_OPENSSL) {// 是否为openssl加密方式
        EVP_CipherUpdate(ctx->ctx, out, (int *) outlen, in, inlen);// 重新进行加密，加密方式EVP_CipherUpdate
    } else if (ctx->cipher == CIPHER_SODIUM) {// 判断sodium加密
        size_t padding = ctx->bytes_remaining;
        memcpy(sodium_buf + padding, in, inlen);
        if (_method == ENCRYPTION_SALSA20) {// 判断加密模式是否为ENCRYPTION_SALSA20
            crypto_stream_salsa20_xor(sodium_buf, sodium_buf, padding + inlen, ctx->iv, _key); // 采用crypto_stream_salsa20_xor_ic加密
        } else if (_method == ENCRYPTION_CHACHA20) {// 判断加密模式是否为ENCRYPTION_CHACHA20
            crypto_stream_chacha20_xor_ic(sodium_buf, sodium_buf, padding + inlen, ctx->iv, ctx->ic, _key);// 采用crypto_stream_chacha20_xor_ic加密
        }
        *outlen = inlen;
        memcpy(out, sodium_buf + padding, inlen);
        padding += inlen;
        ctx->ic += padding / SODIUM_BLOCK_SIZE;
        ctx->bytes_remaining = padding % SODIUM_BLOCK_SIZE;
    }
}
// 加密缓存
void encrypt_buf(struct encryption_ctx *ctx, unsigned char *buf, size_t *len) {
    if (ctx->cipher == CIPHER_TABLE) { // 判断密文是否为表文
        table_encrypt(buf, *len);// 表文加密
    } else {
        if (ctx->status == STATUS_EMPTY) {// 判断状态是否空，为空进行则加上参数并包上密文，不为空则直接包上密文： 这个状态判断是什么？
            size_t iv_len = encryption_iv_len[_method];
            memset(ctx->iv, 0, iv_len);// 归零清整
            RAND_bytes(ctx->iv, iv_len);// 为产生加密的随机数
            init_cipher(ctx, ctx->iv, iv_len, 1);// 初始化密文：暂时这么翻译？
            size_t out_len = *len + ctx->iv_len;
            unsigned char *cipher_text = malloc(out_len);
            cipher_update(ctx, cipher_text, &out_len, buf, *len);// 重新加密
            memcpy(buf, ctx->iv, iv_len);
            memcpy(buf + iv_len, cipher_text, out_len);
            *len = iv_len + out_len;
            free(cipher_text);
        } else {
            size_t out_len = *len + ctx->iv_len;
            unsigned char *cipher_text = malloc(out_len);
            cipher_update(ctx, cipher_text, &out_len, buf, *len);
            memcpy(buf, cipher_text, out_len);
            *len = out_len;
            free(cipher_text); //  释放内存
        }
    }
}

// 解密缓存
void decrypt_buf(struct encryption_ctx *ctx, unsigned char *buf, size_t *len) {
    if (ctx->cipher == CIPHER_TABLE) {// 判断密文是否为表文
        table_decrypt(buf, *len);// 表文解密
    } else {// 否则进行加密处理
        if (ctx->status == STATUS_EMPTY) {
            size_t iv_len = encryption_iv_len[_method];
            memcpy(ctx->iv, buf, iv_len);
            init_cipher(ctx, ctx->iv, iv_len, 0);
            size_t out_len = *len + ctx->iv_len;
            out_len -= iv_len;
            unsigned char *cipher_text = malloc(out_len);
            cipher_update(ctx, cipher_text, &out_len, buf + iv_len, *len - iv_len);
            memcpy(buf, cipher_text, out_len);
            *len = out_len;
            free(cipher_text);
        } else {
            size_t out_len = *len + ctx->iv_len;
            unsigned char *cipher_text = malloc(out_len);
            cipher_update(ctx, cipher_text, &out_len, buf, *len);
            memcpy(buf, cipher_text, out_len);
            *len = out_len;
            free(cipher_text);
        }
    }
}
// 发送密文函数
int send_encrypt(struct encryption_ctx *ctx, int sock, unsigned char *buf, size_t *len, int flags) {
    unsigned char mybuf[4096];
    memcpy(mybuf, buf, *len);
    encrypt_buf(ctx, mybuf, len);// 进行密文加密
    return send(sock, mybuf, *len, flags);// 发送socket子节
}
// 接收密文函数
int recv_decrypt(struct encryption_ctx *ctx, int sock, unsigned char *buf, size_t *len, int flags) {
    char mybuf[4096];
    int result = recv(sock, mybuf, *len, flags);
    memcpy(buf, mybuf, *len);
    decrypt_buf(ctx, buf, len);// 解密
    return result;// 返回解密结果
}
// 初始化密文
void init_cipher(struct encryption_ctx *ctx, const unsigned char *iv, size_t iv_len, int is_cipher) {
    ctx->status = STATUS_INIT;
    if (ctx->cipher == CIPHER_OPENSSL) { // 判断密文是否为openssl
        EVP_CIPHER_CTX_init(ctx->ctx);//EVP_CIPHER_CTX_init 初始化ctx结构体
        EVP_CipherInit_ex(ctx->ctx, _cipher, NULL, NULL, NULL, is_cipher);//该函数采用ENGINE参数impl的算法来设置并初始化加密结构体
        if (!EVP_CIPHER_CTX_set_key_length(ctx->ctx, _key_len)) { // 设置密文长度
            cleanup_encryption(ctx);// 清除原来的密文
            return;
        }
        EVP_CIPHER_CTX_set_padding(ctx->ctx, 1);// 该函数设置是否采用padding功能
        unsigned char *true_key;
        if (_method == ENCRYPTION_RC4_MD5) { // 判断模式是否为RC4_MD5
            unsigned char key_iv[32];
            memcpy(key_iv, _key, 16);
            memcpy(key_iv + 16, iv, 16);
            true_key = MD5(key_iv, 32, NULL); // MD5加密
        } else {
            true_key = _key;
        }
        EVP_CipherInit_ex(ctx->ctx, NULL, NULL, true_key, iv, is_cipher);// 重新初始化ctx
    } else if (ctx->cipher == CIPHER_SODIUM) { // 如果是sodium 模式 则将结构体里的ic 和 bytes_remaining 置0处理
        ctx->ic = 0;
        ctx->bytes_remaining = 0;
    }
    ctx->iv_len = encryption_iv_len[_method];
}
//初始化encryption结构体
void init_encryption(struct encryption_ctx *ctx) {
    ctx->status = STATUS_EMPTY;
    ctx->ctx = EVP_CIPHER_CTX_new();
    ctx->cipher = cipher;
}
//清除密文包
void cleanup_encryption(struct encryption_ctx *ctx) {
    if (ctx->status == STATUS_INIT) {
        if (ctx->cipher == CIPHER_OPENSSL) {
            EVP_CIPHER_CTX_cleanup(ctx->ctx);// 该函数清除一个EVP_CIPHER_CTX结构中的所有信息并释放该结构占用的所有内存
        }
        ctx->status = STATUS_DESTORYED;
    }
}
//确认密文收取，并确定整个encryption的值
void config_encryption(const char *password, const char *method) {
    SSLeay_add_all_algorithms();
    sodium_init();
    _method = encryption_method_from_string(method);
    if (_method == ENCRYPTION_TABLE) {
        get_table((unsigned char *) password);//获取table加密的密文
        cipher = CIPHER_TABLE;
    } else if (_method == ENCRYPTION_SALSA20 || _method == ENCRYPTION_CHACHA20) {
        cipher = CIPHER_SODIUM;
        _key_len = 32;
        unsigned char tmp[EVP_MAX_IV_LENGTH];;
        EVP_BytesToKey(EVP_aes_256_cfb(), EVP_md5(), NULL, (unsigned char *)password,
                                strlen(password), 1, _key, tmp);//给变量key和iv赋值
        shadowsocks_key = _key;
    } else {
        cipher = CIPHER_OPENSSL;
        const char *name = shadowsocks_encryption_names[_method];// 赋值密文名
        if (_method == ENCRYPTION_RC4_MD5) {
            name = "RC4";
        }
        _cipher = EVP_get_cipherbyname(name);// 这三个函数都根据给定的参数返回一个EVP_CIPHER结构
        if (_cipher == NULL) {
//            assert(0);
            // TODO
            printf("_cipher is nil! \r\nThe %s doesn't supported!\r\n please chose anthor!",name);
        } else {
            unsigned char tmp[EVP_MAX_IV_LENGTH];
            _key_len = EVP_BytesToKey(_cipher, EVP_md5(), NULL, (unsigned char *)password,
                                      strlen(password), 1, _key, tmp);
            shadowsocks_key = _key;
        }

//        printf("%d\n", _key_len);
    }
}
