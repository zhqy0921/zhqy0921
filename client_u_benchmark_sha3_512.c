#include "common_auth.h"

static void perf_add(PerfStat* acc, const PerfStat* x) {
    acc->t_rep += x->t_rep;
    acc->t_hpw += x->t_hpw;
    acc->t_check_a += x->t_check_a;
    acc->t_pu += x->t_pu;
    acc->t_ku += x->t_ku;
    acc->t_wu_mu += x->t_wu_mu;
    acc->t_c1_h1 += x->t_c1_h1;
    acc->t_c2_h2 += x->t_c2_h2;
    acc->t_rc_ku_mu += x->t_rc_ku_mu;
    acc->t_rc_verify += x->t_rc_verify;
    acc->t_c3_c4 += x->t_c3_c4;
    acc->t_server_verify += x->t_server_verify;
    acc->t_ps += x->t_ps;
    acc->t_ks += x->t_ks;
    acc->t_ws_mu += x->t_ws_mu;
    acc->t_h5 += x->t_h5;
    acc->t_user_verify_c4 += x->t_user_verify_c4;
    acc->t_user_ks_mu += x->t_user_ks_mu;
    acc->t_user_verify_h5 += x->t_user_verify_h5;
    acc->t_sk_h6 += x->t_sk_h6;
    acc->t_server_verify_h6 += x->t_server_verify_h6;
    acc->t_L1 += x->t_L1;
    acc->t_L2 += x->t_L2;
    acc->t_L3 += x->t_L3;
    acc->t_L4 += x->t_L4;
    acc->t_L5 += x->t_L5;
    acc->t_L6 += x->t_L6;
}

static void perf_divide(PerfStat* out, const PerfStat* in, double d) {
    *out = *in;
    out->t_rep /= d;
    out->t_hpw /= d;
    out->t_check_a /= d;
    out->t_pu /= d;
    out->t_ku /= d;
    out->t_wu_mu /= d;
    out->t_c1_h1 /= d;
    out->t_c2_h2 /= d;
    out->t_rc_ku_mu /= d;
    out->t_rc_verify /= d;
    out->t_c3_c4 /= d;
    out->t_server_verify /= d;
    out->t_ps /= d;
    out->t_ks /= d;
    out->t_ws_mu /= d;
    out->t_h5 /= d;
    out->t_user_verify_c4 /= d;
    out->t_user_ks_mu /= d;
    out->t_user_verify_h5 /= d;
    out->t_sk_h6 /= d;
    out->t_server_verify_h6 /= d;
    out->t_L1 /= d;
    out->t_L2 /= d;
    out->t_L3 /= d;
    out->t_L4 /= d;
    out->t_L5 /= d;
    out->t_L6 /= d;
}

int main(int argc, char** argv) {
    DemoContext ctx;
    Msg1 m1;
    Msg4 m4;
    Msg5 m5;
    UserRuntime urt1, urt2;
    PerfStat perf_sum, perf_one, perf_avg;
    socket_t sock;
    const char* server_ip;
    uint16_t port;
    int rounds;
    int i;
    const char* id = "user001";
    const char* pw = "pass123456";
    const char* bio = "fingerprint-demo";
    double wall_sum = 0.0;
    double wall_start, wall_end;

    if (argc < 4) {
        printf("Usage: %s <SERVER_IP> <PORT> <ROUNDS> [ID] [PW] [BIO]\n", argv[0]);
        return 1;
    }
    server_ip = argv[1];
    port = (uint16_t)atoi(argv[2]);
    rounds = atoi(argv[3]);
    if (argc >= 5) id = argv[4];
    if (argc >= 6) pw = argv[5];
    if (argc >= 7) bio = argv[6];
    if (rounds <= 0) {
        printf("[U] invalid ROUNDS: %d\n", rounds);
        return 1;
    }

    perf_zero(&perf_sum);
    demo_load_user_client(&ctx);
    print_message_bits();

    if (!net_init()) {
        printf("[U] net_init failed.\n");
        return 1;
    }

    printf("[U] benchmark mode: %d rounds\n", rounds);
    for (i = 0; i < rounds; i++) {
        perf_zero(&perf_one);
        wall_start = now_us();

        if (!user_build_M1(&ctx, id, pw, bio, &m1, &urt1, &perf_one)) {
            net_cleanup();
            demo_cleanup(&ctx);
            return 1;
        }

        sock = connect_to_server(server_ip, port);
        if ((intptr_t)sock == -1) {
            printf("[U] connect failed at round %d.\n", i + 1);
            net_cleanup();
            demo_cleanup(&ctx);
            return 1;
        }

        if (!send_all(sock, &m1, sizeof(m1))) {
            printf("[U] send M1 failed at round %d.\n", i + 1);
            close_socket_x(sock);
            net_cleanup();
            demo_cleanup(&ctx);
            return 1;
        }

        if (!recv_all(sock, &m4, sizeof(m4))) {
            printf("[U] recv M4 failed at round %d.\n", i + 1);
            close_socket_x(sock);
            net_cleanup();
            demo_cleanup(&ctx);
            return 1;
        }

        if (!user_process_M4(&ctx, &m4, &urt1, &m5, &urt2, &perf_one)) {
            close_socket_x(sock);
            net_cleanup();
            demo_cleanup(&ctx);
            return 1;
        }

        if (!send_all(sock, &m5, sizeof(m5))) {
            printf("[U] send M5 failed at round %d.\n", i + 1);
            close_socket_x(sock);
            net_cleanup();
            demo_cleanup(&ctx);
            return 1;
        }

        close_socket_x(sock);
        wall_end = now_us();
        wall_sum += (wall_end - wall_start);
        perf_add(&perf_sum, &perf_one);

        if (((i + 1) % 10) == 0) {
            int projected = (int)(((long long)(i + 1) * 10000LL) / (long long)rounds);
            projected = ((projected + 500) / 1000) * 1000;
            if (projected < 1000) projected = 1000;
            if (projected > 10000) projected = 10000;
            printf("[U] round %d/10000 finished\n", projected);
        }
    }

    perf_divide(&perf_avg, &perf_sum, (double)rounds);
    printf("\n[U] last session key SK\n");
    print_hex("SK", urt2.session_key, HASH_BYTES);
    printf("[U] average wall-clock per round (network included): %.2f us\n", wall_sum / (double)rounds);
    printf("[U] average crypto timings over %d actual rounds\n", rounds);
    print_perf_user(&perf_avg);

    net_cleanup();
    demo_cleanup(&ctx);
    return 0;
}
