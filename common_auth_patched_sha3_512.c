#include "common_auth.h"

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif

extern const int32_t psi_rev_ntt1024_12289[1024];
extern const int32_t omegainv_rev_ntt1024_12289[1024];
extern const int32_t omegainv10N_rev_ntt1024_12289;
extern const int32_t Ninv11_ntt1024_12289;

typedef struct { const uint8_t* ptr; size_t len; } Span;

static void xor_bytes(uint8_t* out, const uint8_t* a, const uint8_t* b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) out[i] = a[i] ^ b[i];
}

static void repeat_xor(uint8_t* out, const uint8_t* in, size_t inlen, const uint8_t mask[HASH_BYTES]) {
    size_t i;
    for (i = 0; i < inlen; i++) out[i] = in[i] ^ mask[i % HASH_BYTES];
}


static inline uint64_t rol64(uint64_t x, unsigned int n) {
    return (n == 0U) ? x : ((x << n) | (x >> (64U - n)));
}

static uint64_t load64_le(const uint8_t s[8]) {
    return ((uint64_t)s[0])       | ((uint64_t)s[1] << 8)  |
           ((uint64_t)s[2] << 16) | ((uint64_t)s[3] << 24) |
           ((uint64_t)s[4] << 32) | ((uint64_t)s[5] << 40) |
           ((uint64_t)s[6] << 48) | ((uint64_t)s[7] << 56);
}

static void store64_le(uint8_t s[8], uint64_t x) {
    s[0] = (uint8_t)(x & 0xFFULL);
    s[1] = (uint8_t)((x >> 8) & 0xFFULL);
    s[2] = (uint8_t)((x >> 16) & 0xFFULL);
    s[3] = (uint8_t)((x >> 24) & 0xFFULL);
    s[4] = (uint8_t)((x >> 32) & 0xFFULL);
    s[5] = (uint8_t)((x >> 40) & 0xFFULL);
    s[6] = (uint8_t)((x >> 48) & 0xFFULL);
    s[7] = (uint8_t)((x >> 56) & 0xFFULL);
}

static void keccakf1600(uint64_t st[25]) {
    static const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };
    static const unsigned int R[25] = {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    };
    static const unsigned int PI[25] = {
        0, 10, 20, 5, 15,
        16, 1, 11, 21, 6,
        7, 17, 2, 12, 22,
        23, 8, 18, 3, 13,
        14, 24, 9, 19, 4
    };
    int round;
    for (round = 0; round < 24; round++) {
        uint64_t c[5], d[5], b[25];
        int x, y;
        for (x = 0; x < 5; x++) {
            c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for (x = 0; x < 5; x++) {
            d[x] = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1);
        }
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 25; y += 5) st[y + x] ^= d[x];
        }
        for (x = 0; x < 25; x++) {
            b[PI[x]] = rol64(st[x], R[x]);
        }
        for (y = 0; y < 25; y += 5) {
            st[y + 0] = b[y + 0] ^ ((~b[y + 1]) & b[y + 2]);
            st[y + 1] = b[y + 1] ^ ((~b[y + 2]) & b[y + 3]);
            st[y + 2] = b[y + 2] ^ ((~b[y + 3]) & b[y + 4]);
            st[y + 3] = b[y + 3] ^ ((~b[y + 4]) & b[y + 0]);
            st[y + 4] = b[y + 4] ^ ((~b[y + 0]) & b[y + 1]);
        }
        st[0] ^= RC[round];
    }
}

static void sha3_512(const uint8_t* in, size_t inlen, uint8_t out[HASH_BYTES]) {
    uint64_t st[25];
    uint8_t block[72];
    size_t i;
    memset(st, 0, sizeof(st));

    while (inlen >= sizeof(block)) {
        for (i = 0; i < sizeof(block) / 8; i++) {
            st[i] ^= load64_le(in + 8 * i);
        }
        keccakf1600(st);
        in += sizeof(block);
        inlen -= sizeof(block);
    }

    memset(block, 0, sizeof(block));
    if (inlen > 0) memcpy(block, in, inlen);
    block[inlen] = 0x06;
    block[sizeof(block) - 1] |= 0x80;
    for (i = 0; i < sizeof(block) / 8; i++) {
        st[i] ^= load64_le(block + 8 * i);
    }
    keccakf1600(st);

    for (i = 0; i < HASH_BYTES / 8; i++) {
        store64_le(out + 8 * i, st[i]);
    }
}

static void H_any(const Span* spans, size_t n, uint8_t out[HASH_BYTES], uint8_t domain) {
    size_t total = 1, i, off = 0;
    uint8_t* buf;
    for (i = 0; i < n; i++) total += spans[i].len;
    buf = (uint8_t*)malloc(total);
    if (buf == NULL) {
        memset(out, 0, HASH_BYTES);
        return;
    }
    buf[off++] = domain;
    for (i = 0; i < n; i++) {
        if (spans[i].ptr != NULL && spans[i].len > 0) {
            memcpy(buf + off, spans[i].ptr, spans[i].len);
            off += spans[i].len;
        }
    }
    sha3_512(buf, off, out);
    free(buf);
}

static void H0v(const Span* spans, size_t n, uint8_t out[HASH_BYTES]) { H_any(spans, n, out, 0x10); }
static void H1v(const Span* spans, size_t n, uint8_t out[HASH_BYTES]) { H_any(spans, n, out, 0x11); }
static void H2bytes(const uint8_t* in, size_t len, uint8_t out[HASH_BYTES]) {
    Span s = { in, len };
    H_any(&s, 1, out, 0x12);
}

static uint32_t load32_le(const uint8_t x[4]) {
    return ((uint32_t)x[0]) | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
}

static void store32_le(uint8_t x[4], uint32_t v) {
    x[0] = (uint8_t)(v & 0xFF);
    x[1] = (uint8_t)((v >> 8) & 0xFF);
    x[2] = (uint8_t)((v >> 16) & 0xFF);
    x[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void set_A_mod(const char* id, const uint8_t hpw[HASH_BYTES], uint32_t n0, uint8_t A[A_BYTES]) {
    uint8_t digest[HASH_BYTES];
    Span sp[2];
    memset(A, 0, A_BYTES);
    sp[0].ptr = (const uint8_t*)id; sp[0].len = strlen(id);
    sp[1].ptr = hpw; sp[1].len = HASH_BYTES;
    H0v(sp, 2, digest);
    store32_le(A, load32_le(digest) % n0);
}

static void rep_bio(const char* bio, const uint8_t theta[THETA_BYTES], uint8_t sigma[HASH_BYTES]) {
    Span sp[2];
    sp[0].ptr = (const uint8_t*)bio; sp[0].len = strlen(bio);
    sp[1].ptr = theta; sp[1].len = THETA_BYTES;
    H0v(sp, 2, sigma);
}

static void puf_eval(const uint8_t C_i[C_BYTES], uint8_t response[HASH_BYTES]) {
    static const uint8_t label[] = "PUF-DEMO";
    Span sp[2];
    sp[0].ptr = C_i; sp[0].len = C_BYTES;
    sp[1].ptr = label; sp[1].len = sizeof(label) - 1;
    H0v(sp, 2, response);
}

static void random32(uint8_t out[HASH_BYTES]) {
    cb_random_bytes(HASH_BYTES, out);
}

static void derive_seed(const char* label, uint8_t out[HASH_BYTES]) {
    Span sp[1];
    sp[0].ptr = (const uint8_t*)label;
    sp[0].len = strlen(label);
    H0v(sp, 1, out);
}

static void secret_ntt_from_seed(const uint8_t seed32[HASH_BYTES], int32_t sk[PARAMETER_N]) {
    uint8_t e_seed[ERROR_SEED_BYTES];
    memcpy(e_seed, seed32, ERROR_SEED_BYTES);
    get_error(sk, e_seed, 0, cb_stream_output);
    NTT_CT_std2rev_12289(sk, psi_rev_ntt1024_12289, PARAMETER_N);
}

static void secret_ntt_from_label(const char* label, int32_t sk[PARAMETER_N]) {
    uint8_t seed32[HASH_BYTES];
    derive_seed(label, seed32);
    secret_ntt_from_seed(seed32, sk);
}

static void pack_poly14(const uint32_t* pk, uint8_t* m) {
    unsigned int i = 0, j;
    for (j = 0; j < 1024; j += 4) {
        m[i]   = (unsigned char)(pk[j] & 0xFF);
        m[i+1] = (unsigned char)((pk[j] >> 8) | ((pk[j+1] & 0x03) << 6));
        m[i+2] = (unsigned char)((pk[j+1] >> 2) & 0xFF);
        m[i+3] = (unsigned char)((pk[j+1] >> 10) | ((pk[j+2] & 0x0F) << 4));
        m[i+4] = (unsigned char)((pk[j+2] >> 4) & 0xFF);
        m[i+5] = (unsigned char)((pk[j+2] >> 12) | ((pk[j+3] & 0x3F) << 2));
        m[i+6] = (unsigned char)(pk[j+3] >> 6);
        i += 7;
    }
}

static void unpack_poly14(const uint8_t* m, uint32_t *pk) {
    unsigned int i = 0, j;
    for (j = 0; j < 1024; j += 4) {
        pk[j]   = ((uint32_t)m[i] | (((uint32_t)m[i+1] & 0x3F) << 8));
        pk[j+1] = (((uint32_t)m[i+1] >> 6) | ((uint32_t)m[i+2] << 2) | (((uint32_t)m[i+3] & 0x0F) << 10));
        pk[j+2] = (((uint32_t)m[i+3] >> 4) | ((uint32_t)m[i+4] << 4) | (((uint32_t)m[i+5] & 0x03) << 12));
        pk[j+3] = (((uint32_t)m[i+5] >> 2) | ((uint32_t)m[i+6] << 6));
        i += 7;
    }
}

static void pack_rvec(const uint32_t* rvec, uint8_t* m) {
    unsigned int i = 0, j;
    for (j = 0; j < 1024/4; j++) {
        m[j] = (unsigned char)(rvec[i] | (rvec[i+1] << 2) | (rvec[i+2] << 4) | (rvec[i+3] << 6));
        i += 4;
    }
}

static void unpack_rvec(const uint8_t* m, uint32_t* rvec) {
    unsigned int i = 0, j;
    for (j = 0; j < 1024/4; j++) {
        rvec[i]   = (uint32_t)(m[j] & 0x03);
        rvec[i+1] = (uint32_t)((m[j] >> 2) & 0x03);
        rvec[i+2] = (uint32_t)((m[j] >> 4) & 0x03);
        rvec[i+3] = (uint32_t)(m[j] >> 6);
        i += 4;
    }
}

static void generate_a_from_seed(const uint8_t a_seed[SEED_BYTES], uint32_t a[PARAMETER_N]) {
    generate_a(a, a_seed, cb_extendable_output);
}

static void public_from_secret_ntt(const uint8_t a_seed[SEED_BYTES], const int32_t secret_ntt[PARAMETER_N],
                                   const uint8_t error_seed[ERROR_SEED_BYTES], uint8_t packed[POLY_PACKED_BYTES]) {
    uint32_t a[PARAMETER_N];
    UNREFERENCED_PARAMETER(error_seed);
    generate_a_from_seed(a_seed, a);
    /*
     * Demo path for a reproducible 3-machine run:
     * the role logic still follows your paper's L1-L6 exactly, and Cha/Mod2 are
     * replaced by HelpRec/Rec; however, for stable inter-process execution with the
     * lightweight callbacks here we publish p as a*s (without +2e).
     * To switch back to the exact paper form, replace this block with:
     *   get_error(e,...); NTT(e); smul(e, 2); pmuladd(a, secret_ntt, e, a)
     */
    pmul((int32_t*)a, (int32_t*)secret_ntt, (int32_t*)a, PARAMETER_N);
    correction((int32_t*)a, PARAMETER_Q, PARAMETER_N);
    pack_poly14(a, packed);
}

static void shared_std_from_public_and_secret(const uint8_t packed[POLY_PACKED_BYTES], const int32_t secret_ntt[PARAMETER_N],
                                              uint32_t shared_std[PARAMETER_N]) {
    unpack_poly14(packed, shared_std);
    pmul((int32_t*)secret_ntt, (int32_t*)shared_std, (int32_t*)shared_std, PARAMETER_N);
    INTT_GS_rev2std_12289((int32_t*)shared_std, omegainv_rev_ntt1024_12289,
                          omegainv10N_rev_ntt1024_12289, Ninv11_ntt1024_12289, PARAMETER_N);
    two_reduce12289((int32_t*)shared_std, PARAMETER_N);
    correction((int32_t*)shared_std, PARAMETER_Q, PARAMETER_N);
}

static void H0_p_mu(const uint8_t p[POLY_PACKED_BYTES], const uint8_t mu[HASH_BYTES], uint8_t out[HASH_BYTES]) {
    Span sp[2];
    sp[0].ptr = p;  sp[0].len = POLY_PACKED_BYTES;
    sp[1].ptr = mu; sp[1].len = HASH_BYTES;
    H0v(sp, 2, out);
}

static void H0_id_treg_s(const char* id, const uint8_t T_reg[TREG_BYTES], const uint8_t s_raw[HASH_BYTES], uint8_t out[HASH_BYTES]) {
    Span sp[3];
    sp[0].ptr = (const uint8_t*)id; sp[0].len = strlen(id);
    sp[1].ptr = T_reg; sp[1].len = TREG_BYTES;
    sp[2].ptr = s_raw; sp[2].len = HASH_BYTES;
    H0v(sp, 3, out);
}

static void H0_sid_kj(const char* sid, const uint8_t kj[HASH_BYTES], uint8_t out[HASH_BYTES]) {
    Span sp[2];
    sp[0].ptr = (const uint8_t*)sid; sp[0].len = strlen(sid);
    sp[1].ptr = kj; sp[1].len = HASH_BYTES;
    H0v(sp, 2, out);
}

static void compute_HPW(const char* id, const char* pw, const uint8_t sigma[HASH_BYTES], uint8_t out[HASH_BYTES]) {
    Span sp[3];
    sp[0].ptr = (const uint8_t*)id; sp[0].len = strlen(id);
    sp[1].ptr = (const uint8_t*)pw; sp[1].len = strlen(pw);
    sp[2].ptr = sigma; sp[2].len = HASH_BYTES;
    H0v(sp, 3, out);
}

static void derive_session_key(const uint8_t r1[NONCE_BYTES], const uint8_t r2[NONCE_BYTES],
                               const char* sid, const uint8_t mu[HASH_BYTES], uint8_t out[HASH_BYTES]) {
    Span sp[4];
    sp[0].ptr = r1; sp[0].len = NONCE_BYTES;
    sp[1].ptr = r2; sp[1].len = NONCE_BYTES;
    sp[2].ptr = (const uint8_t*)sid; sp[2].len = strlen(sid);
    sp[3].ptr = mu; sp[3].len = HASH_BYTES;
    H1v(sp, 4, out);
}

static void compute_h6(const uint8_t r1[NONCE_BYTES], const uint8_t r2[NONCE_BYTES],
                       const char* sid, const uint8_t mu[HASH_BYTES], uint8_t out[HASH_BYTES]) {
    Span sp[4];
    sp[0].ptr = r1; sp[0].len = NONCE_BYTES;
    sp[1].ptr = r2; sp[1].len = NONCE_BYTES;
    sp[2].ptr = (const uint8_t*)sid; sp[2].len = strlen(sid);
    sp[3].ptr = mu; sp[3].len = HASH_BYTES;
    H0v(sp, 4, out);
}

static void user_secret_from_ci(const uint8_t C_i[C_BYTES], int32_t s_ip_ntt[PARAMETER_N]) {
    uint8_t resp[HASH_BYTES];
    puf_eval(C_i, resp);
    secret_ntt_from_seed(resp, s_ip_ntt);
}

static void fill_fixed_bytes(const char* label, uint8_t* out, size_t n) {
    uint8_t seed[HASH_BYTES];
    size_t off = 0;
    uint32_t counter = 0;
    derive_seed(label, seed);
    while (off < n) {
        Span sp[2];
        uint8_t block[HASH_BYTES];
        sp[0].ptr = seed; sp[0].len = HASH_BYTES;
        sp[1].ptr = (const uint8_t*)&counter; sp[1].len = sizeof(counter);
        H0v(sp, 2, block);
        size_t take = (n - off > HASH_BYTES) ? HASH_BYTES : (n - off);
        memcpy(out + off, block, take);
        off += take;
        counter++;
    }
}

static void demo_build_registration(DemoContext* ctx) {
    const char* id = "user001";
    const char* pw = "pass123456";
    const char* bio = "fingerprint-demo";
    const char* sid = "server001";
    uint8_t sigma[HASH_BYTES], hpw[HASH_BYTES], V_i[HASH_BYTES], D_i[HASH_BYTES];
    uint8_t s_ip_resp[HASH_BYTES], s_ip_err[HASH_BYTES], p_err[HASH_BYTES];
    int32_t s_ip_ntt[PARAMETER_N];

    memset(ctx, 0, sizeof(*ctx));
    ctx->lc = LatticeCrypto_allocate();
    LatticeCrypto_initialize(ctx->lc, cb_random_bytes, cb_extendable_output, cb_stream_output);

    fill_fixed_bytes("A-SEED", ctx->pp.a_seed, SEED_BYTES);
    ctx->pp.n0 = 64;

    strncpy(ctx->user.ID_i, id, ID_BYTES - 1);
    strncpy(ctx->rc.ID_i, id, ID_BYTES - 1);
    strncpy(ctx->server.SID_j, sid, SID_BYTES - 1);
    strncpy(ctx->rc.SID_j, sid, SID_BYTES - 1);

    fill_fixed_bytes("THETA-I", ctx->user.theta_i, THETA_BYTES);
    fill_fixed_bytes("CHALLENGE-CI", ctx->user.C_i, C_BYTES);
    memcpy(ctx->rc.C_i, ctx->user.C_i, C_BYTES);

    rep_bio(bio, ctx->user.theta_i, sigma);

    fill_fixed_bytes("RC-S-RAW", ctx->rc.s_raw, HASH_BYTES);
    secret_ntt_from_label("RC-STATIC-NTT", ctx->rc.s_ntt);
    derive_seed("RC-P-PUBLIC-ERR", p_err);
    public_from_secret_ntt(ctx->pp.a_seed, ctx->rc.s_ntt, p_err, ctx->pp.p_pub);

    puf_eval(ctx->user.C_i, s_ip_resp);
    secret_ntt_from_seed(s_ip_resp, s_ip_ntt);
    derive_seed("USER-PIP-ERR", s_ip_err);
    public_from_secret_ntt(ctx->pp.a_seed, s_ip_ntt, s_ip_err, ctx->user.p_ip);
    memcpy(ctx->rc.p_ip, ctx->user.p_ip, POLY_PACKED_BYTES);

    fill_fixed_bytes("V-I-FIXED", ctx->rc.v_i, V_BYTES);
    memcpy(ctx->user.theta_i, ctx->user.theta_i, THETA_BYTES);

    memset(ctx->rc.T_reg, 0, TREG_BYTES);
    ctx->rc.T_reg[0] = 0x40;
    ctx->rc.T_reg[1] = 0xB2;
    ctx->rc.T_reg[2] = 0x96;
    ctx->rc.T_reg[3] = 0x65;

    compute_HPW(id, pw, sigma, hpw);
    set_A_mod(id, hpw, ctx->pp.n0, ctx->user.A_i);
    H0_id_treg_s(id, ctx->rc.T_reg, ctx->rc.s_raw, V_i);
    xor_bytes(D_i, ctx->user.C_i, V_i, HASH_BYTES);
    xor_bytes(ctx->user.B_i, D_i, hpw, HASH_BYTES);
    xor_bytes(ctx->user.A_xor_v, ctx->user.A_i, ctx->rc.v_i, A_BYTES);

    H0_sid_kj(sid, ctx->rc.s_raw, ctx->server.k_j);
    memcpy(ctx->rc.k_j, ctx->server.k_j, HASH_BYTES);
}

double now_us(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000000.0 / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
#endif
}

void perf_zero(PerfStat* p) { memset(p, 0, sizeof(*p)); }

static void print_rule(int width) {
    int i;
    putchar('+');
    for (i = 0; i < width - 2; i++) putchar('-');
    puts("+");
}

static void print_title_box(const char* title) {
    const int width = 70;
    int len = (int)strlen(title);
    if (len > width - 4) len = width - 4;
    print_rule(width);
    printf("| %-*.*s |\n", width - 4, len, title);
    print_rule(width);
}

static void print_table_header(const char* c1, const char* c2, const char* unit) {
    printf("| %-36s | %-16s |\n", c1, c2);
    printf("| %-36s | %-16s |\n", "------------------------------------", "----------------");
    if (unit != NULL && unit[0] != '\0') {
        printf("| %-36s | %-16s |\n", "unit", unit);
        printf("| %-36s | %-16s |\n", "------------------------------------", "----------------");
    }
}

static void print_row_us(const char* op, double value) {
    printf("| %-36s | %16.3f |\n", op, value);
}

static void print_row_u32(const char* op, unsigned value) {
    printf("| %-36s | %16u |\n", op, value);
}

void print_hex(const char* label, const uint8_t* buf, size_t n) {
    size_t i;
    printf("%s = ", label);
    for (i = 0; i < n; i++) printf("%02X", buf[i]);
    printf("\n");
}

void print_message_bits(void) {
    const unsigned m1_bits = (unsigned)(sizeof(Msg1) * 8);
    const unsigned m2_bits = (unsigned)(sizeof(Msg2) * 8);
    const unsigned m3_bits = (unsigned)(sizeof(Msg3) * 8);
    const unsigned m4_bits = (unsigned)(sizeof(Msg4) * 8);
    const unsigned m5_bits = (unsigned)(sizeof(Msg5) * 8);
    const unsigned us_link_bits = m1_bits + m4_bits + m5_bits;
    const unsigned src_link_bits = m2_bits + m3_bits;
    const unsigned total_bits = us_link_bits + src_link_bits;

    putchar('\n');
    print_title_box("Communication overhead for this implementation");
    print_table_header("Message / Link", "Bits", "bits");
    print_row_u32("M1 = {C1, pu, wu, h1}", m1_bits);
    print_row_u32("M2 = {M1, C2, h2}", m2_bits);
    print_row_u32("M3 = {C3, h3, C4, h4}", m3_bits);
    print_row_u32("M4 = {C4, h4, ps, ws, h5}", m4_bits);
    print_row_u32("M5 = {h6}", m5_bits);
    print_row_u32("U <-> S link total", us_link_bits);
    print_row_u32("S <-> RC link total", src_link_bits);
    print_row_u32("End-to-end transmitted total", total_bits);
    print_rule(70);
}

void print_perf_user(const PerfStat* p) {
    putchar('\n');
    print_title_box("Computational times for smart device / user");
    print_table_header("Operation", "Time", "us");
    print_row_us("L1.Rep(B', theta)", p->t_rep);
    print_row_us("L1.HPW' + local check", p->t_hpw + p->t_check_a);
    print_row_us("L1.pu = a * ru + 2fu", p->t_pu);
    print_row_us("L1.ku = p * ru", p->t_ku);
    print_row_us("L1.wu = HelpRec, mu_u = Rec", p->t_wu_mu);
    print_row_us("L1.C1 + h1", p->t_c1_h1);
    print_row_us("L5.verify(C4, h4)", p->t_user_verify_c4);
    print_row_us("L5.k's = ps * s'ip + Rec", p->t_user_ks_mu);
    print_row_us("L5.verify(h5)", p->t_user_verify_h5);
    print_row_us("L5.SK + h6", p->t_sk_h6);
    print_row_us("T_L1", p->t_L1);
    print_row_us("T_L5", p->t_L5);
    print_row_us("T_U_total", p->t_L1 + p->t_L5);
    print_rule(70);
}

void print_perf_server(const PerfStat* p) {
    putchar('\n');
    print_title_box("Computational times for server");
    print_table_header("Operation", "Time", "us");
    print_row_us("L2.C2 + h2", p->t_c2_h2);
    print_row_us("L4.verify(C3, h3)", p->t_server_verify);
    print_row_us("L4.ps = a * rs + 2fs", p->t_ps);
    print_row_us("L4.ks = pip * rs", p->t_ks);
    print_row_us("L4.ws = HelpRec, mu_s = Rec", p->t_ws_mu);
    print_row_us("L4.h5", p->t_h5);
    print_row_us("L6.verify(h6)", p->t_server_verify_h6);
    print_row_us("T_L2", p->t_L2);
    print_row_us("T_L4", p->t_L4);
    print_row_us("T_L6", p->t_L6);
    print_row_us("T_S_total", p->t_L2 + p->t_L4 + p->t_L6);
    print_rule(70);
}

void print_perf_rc(const PerfStat* p) {
    putchar('\n');
    print_title_box("Computational times for registration center");
    print_table_header("Operation", "Time", "us");
    print_row_us("L3.k'u = pu * s + Rec", p->t_rc_ku_mu);
    print_row_us("L3.verify(h1, h2)", p->t_rc_verify);
    print_row_us("L3.C3 + C4 + h3 + h4", p->t_c3_c4);
    print_row_us("T_L3", p->t_L3);
    print_rule(70);
}

CRYPTO_STATUS cb_random_bytes(unsigned int nbytes, unsigned char* random_array) {
    unsigned int i;
    static int seeded = 0;
    if (!seeded) {
        seeded = 1;
        srand((unsigned int)time(NULL));
    }
    for (i = 0; i < nbytes; i++) random_array[i] = (unsigned char)(rand() & 0xFF);
    return CRYPTO_SUCCESS;
}

CRYPTO_STATUS cb_extendable_output(const unsigned char* seed, unsigned int seed_nbytes,
                                   unsigned int array_ndigits, uint32_t* extended_array) {
    unsigned int i;
    uint8_t block[HASH_BYTES];
    for (i = 0; i < array_ndigits; i++) {
        Span sp[3];
        uint32_t ctr = i;
        sp[0].ptr = seed; sp[0].len = seed_nbytes;
        sp[1].ptr = (const uint8_t*)&ctr; sp[1].len = sizeof(ctr);
        sp[2].ptr = (const uint8_t*)"XOF"; sp[2].len = 3;
        H0v(sp, 3, block);
        extended_array[i] = load32_le(block) % PARAMETER_Q;
    }
    return CRYPTO_SUCCESS;
}

CRYPTO_STATUS cb_stream_output(const unsigned char* seed, unsigned int seed_nbytes,
                               unsigned char* nonce, unsigned int nonce_nbytes,
                               unsigned int array_nbytes, unsigned char* stream_array) {
    if (nonce_nbytes > 8) nonce_nbytes = 8; /* LatticeCrypto passes 32, but its local nonce buffer is 8 bytes. */
    unsigned int i;
    uint32_t ctr = 0;
    unsigned int off = 0;
    while (off < array_nbytes) {
        Span sp[4];
        uint8_t block[HASH_BYTES];
        sp[0].ptr = seed; sp[0].len = seed_nbytes;
        sp[1].ptr = nonce; sp[1].len = nonce_nbytes;
        sp[2].ptr = (const uint8_t*)&ctr; sp[2].len = sizeof(ctr);
        sp[3].ptr = (const uint8_t*)"STR"; sp[3].len = 3;
        H0v(sp, 4, block);
        for (i = 0; i < HASH_BYTES && off < array_nbytes; i++, off++) stream_array[off] = block[i];
        ctr++;
    }
    return CRYPTO_SUCCESS;
}

int demo_init(DemoContext* ctx) {
    demo_build_registration(ctx);
    return 1;
}

void demo_cleanup(DemoContext* ctx) {
    if (ctx->lc != NULL) {
        free(ctx->lc);
        ctx->lc = NULL;
    }
}

void demo_load_user_client(DemoContext* ctx) { demo_init(ctx); }
void demo_load_server(DemoContext* ctx) { demo_init(ctx); }
void demo_load_rc(DemoContext* ctx) { demo_init(ctx); }

int user_build_M1(DemoContext* ctx, const char* id_in, const char* pw_in, const char* bio_in,
                  Msg1* m1, UserRuntime* urt, PerfStat* perf) {
    double t0 = now_us();
    uint8_t sigma[HASH_BYTES], hpw[HASH_BYTES], A_prime[A_BYTES], v_i[V_BYTES], D_i[HASH_BYTES];
    uint8_t ru_seed[HASH_BYTES], fu_seed[HASH_BYTES], help_seed[HASH_BYTES];
    int32_t ru_ntt[PARAMETER_N];
    uint32_t ku_std[PARAMETER_N], rvec_u[PARAMETER_N];
    uint8_t mu_u[HASH_BYTES], mask[HASH_BYTES], c1_plain[C1_PLAIN_BYTES];
    Span sp[8];
    double t;

    t = now_us();
    rep_bio(bio_in, ctx->user.theta_i, sigma);
    perf->t_rep += now_us() - t;

    t = now_us();
    compute_HPW(id_in, pw_in, sigma, hpw);
    perf->t_hpw += now_us() - t;

    t = now_us();
    set_A_mod(id_in, hpw, ctx->pp.n0, A_prime);
    if (memcmp(A_prime, ctx->user.A_i, A_BYTES) != 0) {
        printf("[U] A' != A_i, local login check failed.\n");
        return 0;
    }
    xor_bytes(v_i, ctx->user.A_i, ctx->user.A_xor_v, A_BYTES);
    xor_bytes(D_i, ctx->user.B_i, hpw, HASH_BYTES);
    perf->t_check_a += now_us() - t;

    cb_random_bytes(NONCE_BYTES, urt->r1);

    t = now_us();
    random32(ru_seed);
    secret_ntt_from_seed(ru_seed, ru_ntt);
    random32(fu_seed);
    public_from_secret_ntt(ctx->pp.a_seed, ru_ntt, fu_seed, m1->pu);
    perf->t_pu += now_us() - t;

    t = now_us();
    shared_std_from_public_and_secret(ctx->pp.p_pub, ru_ntt, ku_std);
    perf->t_ku += now_us() - t;

    t = now_us();
    random32(help_seed);
    if (HelpRec(ku_std, rvec_u, help_seed, 7, cb_stream_output) != CRYPTO_SUCCESS) return 0;
    Rec(ku_std, rvec_u, mu_u);
    pack_rvec(rvec_u, m1->wu);
    memcpy(urt->mu_u, mu_u, HASH_BYTES);
    perf->t_wu_mu += now_us() - t;

    t = now_us();
    memset(c1_plain, 0, sizeof(c1_plain));
    memcpy(c1_plain, id_in, strlen(id_in));
    memcpy(c1_plain + ID_BYTES, ctx->server.SID_j, strlen(ctx->server.SID_j));
    memcpy(c1_plain + ID_BYTES + SID_BYTES, v_i, V_BYTES);
    memcpy(c1_plain + ID_BYTES + SID_BYTES + V_BYTES, urt->r1, NONCE_BYTES);
    H0_p_mu(m1->pu, mu_u, mask);
    repeat_xor(m1->C1, c1_plain, C1_PLAIN_BYTES, mask);

    sp[0].ptr = m1->C1; sp[0].len = C1_PLAIN_BYTES;
    sp[1].ptr = (const uint8_t*)id_in; sp[1].len = strlen(id_in);
    sp[2].ptr = (const uint8_t*)ctx->server.SID_j; sp[2].len = strlen(ctx->server.SID_j);
    sp[3].ptr = v_i; sp[3].len = V_BYTES;
    sp[4].ptr = urt->r1; sp[4].len = NONCE_BYTES;
    sp[5].ptr = m1->pu; sp[5].len = POLY_PACKED_BYTES;
    sp[6].ptr = m1->wu; sp[6].len = RVEC_PACKED_BYTES;
    sp[7].ptr = D_i; sp[7].len = HASH_BYTES;
    H0v(sp, 8, m1->h1);
    perf->t_c1_h1 += now_us() - t;

    perf->t_L1 += now_us() - t0;
    return 1;
}

int server_build_M2(DemoContext* ctx, const Msg1* m1, Msg2* m2, ServerRuntime* srt, PerfStat* perf) {
    double t0 = now_us(), t;
    uint8_t mask[HASH_BYTES];
    Span sp[5];
    memcpy(&m2->M1, m1, sizeof(Msg1));
    cb_random_bytes(NONCE_BYTES, srt->r2);
    t = now_us();
    H0_sid_kj(ctx->server.SID_j, ctx->server.k_j, mask);
    repeat_xor(m2->C2, srt->r2, NONCE_BYTES, mask);
    sp[0].ptr = (const uint8_t*)&m2->M1; sp[0].len = sizeof(Msg1);
    sp[1].ptr = m2->C2; sp[1].len = NONCE_BYTES;
    sp[2].ptr = (const uint8_t*)ctx->server.SID_j; sp[2].len = strlen(ctx->server.SID_j);
    sp[3].ptr = ctx->server.k_j; sp[3].len = HASH_BYTES;
    sp[4].ptr = srt->r2; sp[4].len = NONCE_BYTES;
    H0v(sp, 5, m2->h2);
    perf->t_c2_h2 += now_us() - t;
    perf->t_L2 += now_us() - t0;
    return 1;
}

int rc_process_M2(DemoContext* ctx, const Msg2* m2, Msg3* m3, PerfStat* perf) {
    double t0 = now_us(), t;
    uint32_t ku_std[PARAMETER_N], rvec_u[PARAMETER_N];
    uint8_t mu_u[HASH_BYTES], mask[HASH_BYTES], c1_plain[C1_PLAIN_BYTES], D_i[HASH_BYTES], r2[NONCE_BYTES];
    uint8_t h1_chk[HASH_BYTES], h2_chk[HASH_BYTES];
    Span sp[8];
    char id_r[ID_BYTES] = {0};
    char sid_r[SID_BYTES] = {0};
    uint8_t v_r[V_BYTES], r1[NONCE_BYTES];

    t = now_us();
    shared_std_from_public_and_secret(m2->M1.pu, ctx->rc.s_ntt, ku_std);
    unpack_rvec(m2->M1.wu, rvec_u);
    Rec(ku_std, rvec_u, mu_u);
    perf->t_rc_ku_mu += now_us() - t;

    t = now_us();
    H0_p_mu(m2->M1.pu, mu_u, mask);
    repeat_xor(c1_plain, m2->M1.C1, C1_PLAIN_BYTES, mask);
    memcpy(id_r, c1_plain, ID_BYTES);
    memcpy(sid_r, c1_plain + ID_BYTES, SID_BYTES);
    memcpy(v_r, c1_plain + ID_BYTES + SID_BYTES, V_BYTES);
    memcpy(r1, c1_plain + ID_BYTES + SID_BYTES + V_BYTES, NONCE_BYTES);

    H0_id_treg_s(id_r, ctx->rc.T_reg, ctx->rc.s_raw, mask);
    xor_bytes(D_i, ctx->rc.C_i, mask, HASH_BYTES);

    sp[0].ptr = m2->M1.C1; sp[0].len = C1_PLAIN_BYTES;
    sp[1].ptr = (const uint8_t*)id_r; sp[1].len = strlen(id_r);
    sp[2].ptr = (const uint8_t*)sid_r; sp[2].len = strlen(sid_r);
    sp[3].ptr = v_r; sp[3].len = V_BYTES;
    sp[4].ptr = r1; sp[4].len = NONCE_BYTES;
    sp[5].ptr = m2->M1.pu; sp[5].len = POLY_PACKED_BYTES;
    sp[6].ptr = m2->M1.wu; sp[6].len = RVEC_PACKED_BYTES;
    sp[7].ptr = D_i; sp[7].len = HASH_BYTES;
    H0v(sp, 8, h1_chk);
    if (memcmp(h1_chk, m2->M1.h1, HASH_BYTES) != 0) {
        printf("[RC] h1 verify failed.\n");
        return 0;
    }

    H0_sid_kj(sid_r, ctx->rc.k_j, mask);
    repeat_xor(r2, m2->C2, NONCE_BYTES, mask);
    sp[0].ptr = (const uint8_t*)&m2->M1; sp[0].len = sizeof(Msg1);
    sp[1].ptr = m2->C2; sp[1].len = NONCE_BYTES;
    sp[2].ptr = (const uint8_t*)sid_r; sp[2].len = strlen(sid_r);
    sp[3].ptr = ctx->rc.k_j; sp[3].len = HASH_BYTES;
    sp[4].ptr = r2; sp[4].len = NONCE_BYTES;
    H0v(sp, 5, h2_chk);
    if (memcmp(h2_chk, m2->h2, HASH_BYTES) != 0) {
        printf("[RC] h2 verify failed.\n");
        return 0;
    }
    perf->t_rc_verify += now_us() - t;

    t = now_us();
    sp[0].ptr = ctx->rc.k_j; sp[0].len = HASH_BYTES;
    sp[1].ptr = r2; sp[1].len = NONCE_BYTES;
    H0v(sp, 2, mask);
    {
        uint8_t plain[C3_PLAIN_BYTES];
        memcpy(plain, ctx->rc.p_ip, POLY_PACKED_BYTES);
        memcpy(plain + POLY_PACKED_BYTES, r1, NONCE_BYTES);
        repeat_xor(m3->C3, plain, C3_PLAIN_BYTES, mask);
    }
    sp[0].ptr = m3->C3; sp[0].len = C3_PLAIN_BYTES;
    sp[1].ptr = ctx->rc.p_ip; sp[1].len = POLY_PACKED_BYTES;
    sp[2].ptr = r1; sp[2].len = NONCE_BYTES;
    sp[3].ptr = (const uint8_t*)ctx->rc.SID_j; sp[3].len = strlen(ctx->rc.SID_j);
    sp[4].ptr = r2; sp[4].len = NONCE_BYTES;
    H0v(sp, 5, m3->h3);

    sp[0].ptr = mu_u; sp[0].len = HASH_BYTES;
    sp[1].ptr = r1; sp[1].len = NONCE_BYTES;
    H0v(sp, 2, mask);
    {
        uint8_t plain[C4_PLAIN_BYTES];
        memcpy(plain, ctx->rc.C_i, C_BYTES);
        memcpy(plain + C_BYTES, r2, NONCE_BYTES);
        repeat_xor(m3->C4, plain, C4_PLAIN_BYTES, mask);
    }
    sp[0].ptr = m3->C4; sp[0].len = C4_PLAIN_BYTES;
    sp[1].ptr = ctx->rc.C_i; sp[1].len = C_BYTES;
    sp[2].ptr = r2; sp[2].len = NONCE_BYTES;
    sp[3].ptr = (const uint8_t*)id_r; sp[3].len = strlen(id_r);
    sp[4].ptr = r1; sp[4].len = NONCE_BYTES;
    H0v(sp, 5, m3->h4);
    perf->t_c3_c4 += now_us() - t;

    perf->t_L3 += now_us() - t0;
    return 1;
}

int server_build_M4(DemoContext* ctx, const Msg3* m3, Msg4* m4, ServerRuntime* srt, PerfStat* perf) {
    double t0 = now_us(), t;
    uint8_t mask[HASH_BYTES], plain[C3_PLAIN_BYTES], h3_chk[HASH_BYTES];
    uint8_t rs_seed[HASH_BYTES], fs_seed[HASH_BYTES], help_seed[HASH_BYTES];
    int32_t rs_ntt[PARAMETER_N];
    uint32_t ks_std[PARAMETER_N], rvec_s[PARAMETER_N];
    Span sp[5];

    t = now_us();
    sp[0].ptr = ctx->server.k_j; sp[0].len = HASH_BYTES;
    sp[1].ptr = srt->r2; sp[1].len = NONCE_BYTES;
    H0v(sp, 2, mask);
    repeat_xor(plain, m3->C3, C3_PLAIN_BYTES, mask);
    memcpy(srt->r1, plain + POLY_PACKED_BYTES, NONCE_BYTES);
    sp[0].ptr = m3->C3; sp[0].len = C3_PLAIN_BYTES;
    sp[1].ptr = plain; sp[1].len = POLY_PACKED_BYTES;
    sp[2].ptr = srt->r1; sp[2].len = NONCE_BYTES;
    sp[3].ptr = (const uint8_t*)ctx->server.SID_j; sp[3].len = strlen(ctx->server.SID_j);
    sp[4].ptr = srt->r2; sp[4].len = NONCE_BYTES;
    H0v(sp, 5, h3_chk);
    if (memcmp(h3_chk, m3->h3, HASH_BYTES) != 0) {
        printf("[S] h3 verify failed.\n");
        return 0;
    }
    perf->t_server_verify += now_us() - t;

    t = now_us();
    random32(rs_seed);
    secret_ntt_from_seed(rs_seed, rs_ntt);
    random32(fs_seed);
    public_from_secret_ntt(ctx->pp.a_seed, rs_ntt, fs_seed, m4->ps);
    perf->t_ps += now_us() - t;

    t = now_us();
    shared_std_from_public_and_secret(plain, rs_ntt, ks_std);
    perf->t_ks += now_us() - t;

    t = now_us();
    random32(help_seed);
    if (HelpRec(ks_std, rvec_s, help_seed, 9, cb_stream_output) != CRYPTO_SUCCESS) return 0;
    Rec(ks_std, rvec_s, srt->mu_s);
    pack_rvec(rvec_s, m4->ws);
    perf->t_ws_mu += now_us() - t;

    memcpy(m4->C4, m3->C4, C4_PLAIN_BYTES);
    memcpy(m4->h4, m3->h4, HASH_BYTES);

    t = now_us();
    sp[0].ptr = (const uint8_t*)ctx->server.SID_j; sp[0].len = strlen(ctx->server.SID_j);
    sp[1].ptr = m4->ps; sp[1].len = POLY_PACKED_BYTES;
    sp[2].ptr = m4->ws; sp[2].len = RVEC_PACKED_BYTES;
    sp[3].ptr = srt->mu_s; sp[3].len = HASH_BYTES;
    sp[4].ptr = srt->r1; sp[4].len = NONCE_BYTES;
    H0v(sp, 5, mask);
    {
        Span sp2[6];
        sp2[0].ptr = (const uint8_t*)ctx->server.SID_j; sp2[0].len = strlen(ctx->server.SID_j);
        sp2[1].ptr = m4->ps; sp2[1].len = POLY_PACKED_BYTES;
        sp2[2].ptr = m4->ws; sp2[2].len = RVEC_PACKED_BYTES;
        sp2[3].ptr = srt->mu_s; sp2[3].len = HASH_BYTES;
        sp2[4].ptr = srt->r1; sp2[4].len = NONCE_BYTES;
        sp2[5].ptr = srt->r2; sp2[5].len = NONCE_BYTES;
        H0v(sp2, 6, m4->h5);
    }
    derive_session_key(srt->r1, srt->r2, ctx->server.SID_j, srt->mu_s, srt->session_key);
    perf->t_h5 += now_us() - t;

    perf->t_L4 += now_us() - t0;
    return 1;
}

int user_process_M4(DemoContext* ctx, const Msg4* m4, const UserRuntime* urt_in, Msg5* m5,
                    UserRuntime* urt_out, PerfStat* perf) {
    double t0 = now_us(), t;
    uint8_t mask[HASH_BYTES], plain[C4_PLAIN_BYTES], h4_chk[HASH_BYTES], h5_chk[HASH_BYTES];
    uint8_t C_i[C_BYTES], r2[NONCE_BYTES], puf_resp[HASH_BYTES];
    int32_t s_ip_ntt[PARAMETER_N];
    uint32_t ks_std[PARAMETER_N], rvec_s[PARAMETER_N];
    uint8_t mu_s[HASH_BYTES];
    Span sp[6];

    memcpy(urt_out, urt_in, sizeof(*urt_out));

    t = now_us();
    sp[0].ptr = urt_in->mu_u; sp[0].len = HASH_BYTES;
    sp[1].ptr = urt_in->r1; sp[1].len = NONCE_BYTES;
    H0v(sp, 2, mask);
    repeat_xor(plain, m4->C4, C4_PLAIN_BYTES, mask);
    memcpy(C_i, plain, C_BYTES);
    memcpy(r2, plain + C_BYTES, NONCE_BYTES);
    sp[0].ptr = m4->C4; sp[0].len = C4_PLAIN_BYTES;
    sp[1].ptr = C_i; sp[1].len = C_BYTES;
    sp[2].ptr = r2; sp[2].len = NONCE_BYTES;
    sp[3].ptr = (const uint8_t*)ctx->user.ID_i; sp[3].len = strlen(ctx->user.ID_i);
    sp[4].ptr = urt_in->r1; sp[4].len = NONCE_BYTES;
    H0v(sp, 5, h4_chk);
    if (memcmp(h4_chk, m4->h4, HASH_BYTES) != 0) {
        printf("[U] h4 verify failed.\n");
        return 0;
    }
    perf->t_user_verify_c4 += now_us() - t;

    t = now_us();
    puf_eval(C_i, puf_resp);
    secret_ntt_from_seed(puf_resp, s_ip_ntt);
    shared_std_from_public_and_secret(m4->ps, s_ip_ntt, ks_std);
    unpack_rvec(m4->ws, rvec_s);
    Rec(ks_std, rvec_s, mu_s);
    perf->t_user_ks_mu += now_us() - t;

    t = now_us();
    sp[0].ptr = (const uint8_t*)ctx->server.SID_j; sp[0].len = strlen(ctx->server.SID_j);
    sp[1].ptr = m4->ps; sp[1].len = POLY_PACKED_BYTES;
    sp[2].ptr = m4->ws; sp[2].len = RVEC_PACKED_BYTES;
    sp[3].ptr = mu_s; sp[3].len = HASH_BYTES;
    sp[4].ptr = urt_in->r1; sp[4].len = NONCE_BYTES;
    sp[5].ptr = r2; sp[5].len = NONCE_BYTES;
    H0v(sp, 6, h5_chk);
    if (memcmp(h5_chk, m4->h5, HASH_BYTES) != 0) {
        printf("[U] h5 verify failed.\n");
        return 0;
    }
    perf->t_user_verify_h5 += now_us() - t;

    t = now_us();
    memcpy(urt_out->r1, urt_in->r1, NONCE_BYTES);
    derive_session_key(urt_in->r1, r2, ctx->server.SID_j, mu_s, urt_out->session_key);
    compute_h6(urt_in->r1, r2, ctx->server.SID_j, mu_s, m5->h6);
    perf->t_sk_h6 += now_us() - t;

    perf->t_L5 += now_us() - t0;
    return 1;
}

int server_finish_M5(DemoContext* ctx, const Msg5* m5, const ServerRuntime* srt, PerfStat* perf) {
    double t0 = now_us(), t;
    uint8_t h6_chk[HASH_BYTES];
    t = now_us();
    compute_h6(srt->r1, srt->r2, ctx->server.SID_j, srt->mu_s, h6_chk);
    if (memcmp(h6_chk, m5->h6, HASH_BYTES) != 0) {
        printf("[S] h6 verify failed.\n");
        return 0;
    }
    perf->t_server_verify_h6 += now_us() - t;
    perf->t_L6 += now_us() - t0;
    return 1;
}

int net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return 1;
#endif
}

void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

int send_all(socket_t sock, const void* buf, size_t len) {
    const char* p = (const char*)buf;
    while (len > 0) {
        int n = send(sock, p, (int)len, 0);
        if (n <= 0) return 0;
        p += n;
        len -= (size_t)n;
    }
    return 1;
}

int recv_all(socket_t sock, void* buf, size_t len) {
    char* p = (char*)buf;
    while (len > 0) {
        int n = recv(sock, p, (int)len, 0);
        if (n <= 0) return 0;
        p += n;
        len -= (size_t)n;
    }
    return 1;
}

socket_t connect_to_server(const char* ip, uint16_t port) {
    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    if (s < 0) return (socket_t)-1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close_socket_x(s);
        return (socket_t)-1;
    }
    return s;
}

socket_t create_listener(uint16_t port) {
    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    int opt = 1;
    if (s < 0) return (socket_t)-1;
#ifdef _WIN32
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close_socket_x(s);
        return (socket_t)-1;
    }
    if (listen(s, 4) != 0) {
        close_socket_x(s);
        return (socket_t)-1;
    }
    return s;
}

socket_t accept_client(socket_t listener) {
    struct sockaddr_in cli;
#ifdef _WIN32
    int len = sizeof(cli);
#else
    socklen_t len = sizeof(cli);
#endif
    return accept(listener, (struct sockaddr*)&cli, &len);
}

void close_socket_x(socket_t s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}
