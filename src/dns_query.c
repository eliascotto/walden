#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <string.h>

// Query DNS directly through the platform resolver. getaddrinfo also reads
// /etc/hosts, where Walden has already installed sinkhole addresses.
int walden_dns_query(const char *name, int record_type, unsigned char *answer,
                     int answer_capacity) {
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) {
        return -1;
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
    res_nclose(&state);
    return length;
}
