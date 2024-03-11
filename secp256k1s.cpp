/*
 * © 2022
 * Author: Akhat T. Kuangaliyev
 * Company: Jupiter Soft
 */
#include "secp256k1s.h"
#include <secp256k1.h>

using namespace Sekura::Crypt;

Secp256k1::Secp256k1(QObject *parent) : QObject{parent} {}

QByteArray Secp256k1::pubkey(const QByteArray &key) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    unsigned char arr[32];
    memcpy(arr, key.data(), 32);
    int res = secp256k1_ec_pubkey_create(ctx, &pubkey, arr);
    QByteArray ret(64, 0);
    if (res == 1) {
        memcpy(ret.data(), pubkey.data, 64);
    }
    secp256k1_context_destroy(ctx);
    return ret;
}

QByteArray Secp256k1::sign(const QByteArray &key, const QByteArray &hash) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    QByteArray ret(64, 0);
    unsigned char arr[32];
    memcpy(arr, key.data(), 32);
    unsigned char hsh[32];
    memcpy(hsh, hash.data(), 32);
    secp256k1_ecdsa_signature signature;
    int res = secp256k1_ecdsa_sign(ctx, &signature, hsh, arr, NULL, NULL);
    if (res == 1) {
        memcpy(ret.data(), signature.data, 64);
    }
    secp256k1_context_destroy(ctx);
    return ret;
}

bool Secp256k1::verify(const QByteArray &signture, const QByteArray &pubkey,
                       const QByteArray &hash) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_signature sig;
    memcpy(sig.data, signture.data(), 64);
    secp256k1_pubkey pbkey;
    memcpy(pbkey.data, pubkey.data(), 64);
    unsigned char hsh[32];
    memcpy(hsh, hash.data(), 32);

    int res = secp256k1_ecdsa_verify(ctx, &sig, hsh, &pbkey);

    secp256k1_context_destroy(ctx);
    if (res == 0)
        return false;
    return true;
}

bool Secp256k1::privkeyvalid(const QByteArray &key) {
    secp256k1_context *ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char pk[32];
    memcpy(pk, key, 32);
    bool ret = false;
    if (secp256k1_ec_seckey_verify(ctx, pk) == 1) {
        ret = true;
    }
    secp256k1_context_destroy(ctx);
    return ret;
}

QByteArray Secp256k1::compress(const QByteArray &pubkey) {
    secp256k1_context *ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey pk;
    memcpy(pk.data, pubkey.data(), 64);
    unsigned char out[33];
    size_t ol = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &ol, &pk, SECP256K1_EC_COMPRESSED);
    QByteArray ret(ol, 0);
    memcpy(ret.data(), out, ol);
    secp256k1_context_destroy(ctx);
    return ret;
}

QByteArray Secp256k1::uncompress(const QByteArray &pubkey) {
    secp256k1_context *ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey pk;
    unsigned char inp[33];
    memcpy(inp, pubkey.data(), 33);
    if (secp256k1_ec_pubkey_parse(ctx, &pk, inp, 33) == 1) {
        QByteArray ret(64, 0);
        memcpy(ret.data(), pk.data, 64);
        secp256k1_context_destroy(ctx);
        return ret;
    }
    secp256k1_context_destroy(ctx);
    return QByteArray();
}
