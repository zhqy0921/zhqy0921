#ifndef COMMON_AUTH_H
#define COMMON_AUTH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#ifndef __WINDOWS__
#define __WINDOWS__
#endif
#else
#ifndef __LINUX__
#define __LINUX__
#endif
#endif

#ifndef _AMD64_
#define _AMD64_
#endif
#ifndef _GENERIC_
#define _GENERIC_
#endif

#include "LatticeCrypto_priv.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
typedef int socket_t;
#endif

#define HASH_BYTES 64
#define NONCE_BYTES 32
#define ID_BYTES 32
#define SID_BYTES 32
#define V_BYTES 32
#define C_BYTES 32
#define THETA_BYTES 32
#define BIO_BYTES 32
#define PW_BYTES 32
#define A_BYTES 32
#define POLY_PACKED_BYTES 1792
#define RVEC_PACKED_BYTES 256
#define TREG_BYTES 8

#define C1_PLAIN_BYTES (ID_BYTES + SID_BYTES + V_BYTES + NONCE_BYTES)
#define C3_PLAIN_BYTES (POLY_PACKED_BYTES + NONCE_BYTES)
#define C4_PLAIN_BYTES (C_BYTES + NONCE_BYTES)

typedef struct {
    uint8_t C1[C1_PLAIN_BYTES];
    uint8_t pu[POLY_PACKED_BYTES];
    uint8_t wu[RVEC_PACKED_BYTES];
    uint8_t h1[HASH_BYTES];
} Msg1;

typedef struct {
    Msg1 M1;
    uint8_t C2[NONCE_BYTES];
    uint8_t h2[HASH_BYTES];
} Msg2;

typedef struct {
    uint8_t C3[C3_PLAIN_BYTES];
    uint8_t h3[HASH_BYTES];
    uint8_t C4[C4_PLAIN_BYTES];
    uint8_t h4[HASH_BYTES];
} Msg3;

typedef struct {
    uint8_t C4[C4_PLAIN_BYTES];
    uint8_t h4[HASH_BYTES];
    uint8_t ps[POLY_PACKED_BYTES];
    uint8_t ws[RVEC_PACKED_BYTES];
    uint8_t h5[HASH_BYTES];
} Msg4;

typedef struct {
    uint8_t h6[HASH_BYTES];
} Msg5;

typedef struct {
    uint8_t a_seed[SEED_BYTES];
    uint8_t p_pub[POLY_PACKED_BYTES];
    uint32_t n0;
} PublicParams;

typedef struct {
    char ID_i[ID_BYTES];
    uint8_t B_i[HASH_BYTES];
    uint8_t A_i[A_BYTES];
    uint8_t A_xor_v[A_BYTES];
    uint8_t theta_i[THETA_BYTES];
    uint8_t C_i[C_BYTES];
    uint8_t p_ip[POLY_PACKED_BYTES];
} UserLocalStore;

typedef struct {
    char SID_j[SID_BYTES];
    uint8_t k_j[HASH_BYTES];
} ServerStore;

typedef struct {
    uint8_t s_raw[HASH_BYTES];
    int32_t s_ntt[PARAMETER_N];
    char ID_i[ID_BYTES];
    uint8_t T_reg[TREG_BYTES];
    uint8_t v_i[V_BYTES];
    uint8_t C_i[C_BYTES];
    uint8_t p_ip[POLY_PACKED_BYTES];
    char SID_j[SID_BYTES];
    uint8_t k_j[HASH_BYTES];
} RCStore;

typedef struct {
    PLatticeCryptoStruct lc;
    PublicParams pp;
    UserLocalStore user;
    ServerStore server;
    RCStore rc;
} DemoContext;

typedef struct {
    double t_rep;
    double t_hpw;
    double t_check_a;
    double t_pu;
    double t_ku;
    double t_wu_mu;
    double t_c1_h1;
    double t_c2_h2;
    double t_rc_ku_mu;
    double t_rc_verify;
    double t_c3_c4;
    double t_server_verify;
    double t_ps;
    double t_ks;
    double t_ws_mu;
    double t_h5;
    double t_user_verify_c4;
    double t_user_ks_mu;
    double t_user_verify_h5;
    double t_sk_h6;
    double t_server_verify_h6;
    double t_L1;
    double t_L2;
    double t_L3;
    double t_L4;
    double t_L5;
    double t_L6;
} PerfStat;

typedef struct {
    uint8_t mu_u[HASH_BYTES];
    uint8_t r1[NONCE_BYTES];
    uint8_t session_key[HASH_BYTES];
} UserRuntime;

typedef struct {
    uint8_t mu_s[HASH_BYTES];
    uint8_t r1[NONCE_BYTES];
    uint8_t r2[NONCE_BYTES];
    uint8_t session_key[HASH_BYTES];
} ServerRuntime;

double now_us(void);
void perf_zero(PerfStat* p);
void print_hex(const char* label, const uint8_t* buf, size_t n);
void print_message_bits(void);
void print_perf_user(const PerfStat* p);
void print_perf_server(const PerfStat* p);
void print_perf_rc(const PerfStat* p);

CRYPTO_STATUS cb_random_bytes(unsigned int nbytes, unsigned char* random_array);
CRYPTO_STATUS cb_extendable_output(const unsigned char* seed, unsigned int seed_nbytes,
                                   unsigned int array_ndigits, uint32_t* extended_array);
CRYPTO_STATUS cb_stream_output(const unsigned char* seed, unsigned int seed_nbytes,
                               unsigned char* nonce, unsigned int nonce_nbytes,
                               unsigned int array_nbytes, unsigned char* stream_array);

int demo_init(DemoContext* ctx);
void demo_cleanup(DemoContext* ctx);
void demo_load_user_client(DemoContext* ctx);
void demo_load_server(DemoContext* ctx);
void demo_load_rc(DemoContext* ctx);

int user_build_M1(DemoContext* ctx, const char* id_in, const char* pw_in, const char* bio_in,
                  Msg1* m1, UserRuntime* urt, PerfStat* perf);
int server_build_M2(DemoContext* ctx, const Msg1* m1, Msg2* m2, ServerRuntime* srt, PerfStat* perf);
int rc_process_M2(DemoContext* ctx, const Msg2* m2, Msg3* m3, PerfStat* perf);
int server_build_M4(DemoContext* ctx, const Msg3* m3, Msg4* m4, ServerRuntime* srt, PerfStat* perf);
int user_process_M4(DemoContext* ctx, const Msg4* m4, const UserRuntime* urt_in, Msg5* m5,
                    UserRuntime* urt_out, PerfStat* perf);
int server_finish_M5(DemoContext* ctx, const Msg5* m5, const ServerRuntime* srt, PerfStat* perf);

int net_init(void);
void net_cleanup(void);
int send_all(socket_t sock, const void* buf, size_t len);
int recv_all(socket_t sock, void* buf, size_t len);
socket_t connect_to_server(const char* ip, uint16_t port);
socket_t create_listener(uint16_t port);
socket_t accept_client(socket_t listener);
void close_socket_x(socket_t s);

#endif
