# MQTTs client with Post-Quantum TLS Using mbedtls
The project is meant to showcase the Hybrid Post-Quantum capabilities of an MQTTs client using TLS 1.3 and the mbedtls library. \
For info or comments, contact us at hello@securitypattern.com
# mbedtls
## Introduction of Hybrid Post-Quantum cryptography 

The TLS handshake has been agumented with Hybrid PQ capabilities by introducing a new KEM and a new signature mechanism. \
These are, respectively X25519-MLKEM768 and Ed25519-MLDSA.

The functions responsible for the KEM can be found in [qubip.c](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/main/stm32_f429/Middlewares/Third_Party/MBEDTLS/library/qubip.c):
```
HybridKeyKEM *hybrid_key_gen();
void hybrid_key_free(HybridKeyKEM *);
```
The signature and signature verification functions are implemented in the already present mbedtls file [pk_wrap.c](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/8651821b60df32601ef3e36d88d89c398002bf2e/stm32_f429/Middlewares/Third_Party/MBEDTLS/library/pk_wrap.c#L1363) that get called several times during the TLS handshake.

```
static int ed25519_mlds44_sign_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng);

static int ed25519_mlds44_verify_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		const unsigned char *sig, size_t sig_len);
```

Furthermore, the certificate parsing functionalities have been expanded to include support for Hybrid PQ certificates in file [pk_parse.c](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/main/stm32_f429/Middlewares/Third_Party/MBEDTLS/library/pkparse.c#L594)

A few examples of Hybrid PQ certificates have been hardcoded in file [MQTTInterface.c](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/main/stm32_f429/Middlewares/Third_Party/MQTT/MQTTInterface.c#L485)

The ID definitions for the Hybrid mechanism are as follows:
```
#define MBEDTLS_SSL_IANA_TLS_GROUP_MLKEM768 0x11ec
#define MBEDTLS_TLS1_3_SIG_ED25519_MLDSA44 0x090a
#define MBEDTLS_TLS1_3_SIG_ED25519_MLDSA65 0x090b
```
as shown in file [ssl.h](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/main/stm32_f429/Middlewares/Third_Party/MBEDTLS/include/mbedtls/ssl.h)
