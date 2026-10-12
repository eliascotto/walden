#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <string.h>

// Query DNS directly through the platform resolver. getaddrinfo also reads
// /etc/hosts, where Walden has already installed sinkhole addresses.
static int query(const char *name, int record_type, unsigned char *answer,
                 int answer_capacity, int *failure_kind, unsigned short test_port) {
    *failure_kind = 2; // temporary failure unless proven to be a negative answer
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) {
        return -1;
    }

    // Override machine-wide resolver retries for this private query state.
    // Each server gets a short wait and only one resolver attempt; a dead
    // hostname must not occupy a worker through the system's long defaults.
    state.retrans = 2;
    state.retry = 1;
    // Darwin's native TCP fallback has blocking connect/read calls without
    // this UDP deadline. A truncated UDP answer is returned to Rust as an
    // incomplete lookup; hosts coverage and previous addresses are retained.
    state.options &= ~RES_USEVC;
    state.options |= RES_IGNTC;

    if (test_port != 0) {
        state.nscount = 1;
        memset(&state.nsaddr_list[0], 0, sizeof(state.nsaddr_list[0]));
        state.nsaddr_list[0].sin_family = AF_INET;
#ifdef __APPLE__
        state.nsaddr_list[0].sin_len = sizeof(state.nsaddr_list[0]);
#endif
        state.nsaddr_list[0].sin_port = htons(test_port);
        state.nsaddr_list[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

#ifdef __linux__
    // systemd-resolved's 127.0.0.53 stub synthesizes /etc/hosts answers.
    // Its 127.0.0.54 proxy forwards DNS without those local records.
    struct in_addr stub;
    struct in_addr proxy;
    inet_pton(AF_INET, "127.0.0.53", &stub);
    inet_pton(AF_INET, "127.0.0.54", &proxy);
    for (int i = 0; i < state.nscount; ++i) {
        if (state.nsaddr_list[i].sin_family == AF_INET &&
            state.nsaddr_list[i].sin_addr.s_addr == stub.s_addr) {
            state.nsaddr_list[i].sin_addr = proxy;
        }
    }
#endif

    int length = res_nquery(&state, name, ns_c_in, record_type, answer,
                            answer_capacity);
    if (length > 0) {
        *failure_kind = 0;
    } else if (state.res_h_errno == HOST_NOT_FOUND || state.res_h_errno == NO_DATA) {
        *failure_kind = 1;
    }
    res_nclose(&state);
    return length;
}

int walden_dns_query(const char *name, int record_type, unsigned char *answer,
                     int answer_capacity, int *failure_kind) {
    return query(name, record_type, answer, answer_capacity, failure_kind, 0);
}

// Used only by Rust unit tests to exercise a nonresponding local DNS server.
int walden_dns_query_test(const char *name, int record_type, unsigned char *answer,
                          int answer_capacity, int *failure_kind, unsigned short port) {
    return query(name, record_type, answer, answer_capacity, failure_kind, port);
}
