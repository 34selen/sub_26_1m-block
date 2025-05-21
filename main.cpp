#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/types.h>

#include <netinet/in.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string>
#include <unordered_set>
#include <iostream>
#include <fstream>
#include <iso646.h>

std::string method[9] = {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
std::unordered_set<std::string> block;

std::string host_from_packet(const char *packet, unsigned int len)
{
    int index = 0;
    while ((index < len) and (strncmp("Host:", packet, 5)))
    {
        index++;
        packet++;
    }
    if (index == len)
        return NULL;

    packet += 5;
    if (*packet == ' ')
        packet++;

    std::string tmp;
    while (*packet not_eq '\r')
        tmp += *packet++;
    return tmp;
}

static bool check_host(unsigned char *packet, unsigned int len)
{
    struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *)packet;

    if (ipv4->ip_p not_eq IPPROTO_TCP)
        return false;
    struct libnet_tcp_hdr *TCP = (struct libnet_tcp_hdr *)(packet + ipv4->ip_hl * 4);
    const char *payload = (const char *)(packet + ipv4->ip_hl * 4 + TCP->th_off * 4);

    if ((ntohs(TCP->th_sport) not_eq 80) and (ntohs(TCP->th_dport) not_eq 80))
        return false;

    bool IsHTTP = false;
    for (std::string str : method)
    {
        if (IsHTTP)
            break;
        IsHTTP |= (not strncmp(str.c_str(), payload, str.size()));
    }
    if (not IsHTTP)
        return false;

    std::string host = host_from_packet(payload, len);
    auto iter = block.find(host);
    if (iter == block.end())
        return false;

    printf("BLOCK!! : %s\n", host.c_str());
    return true;
}

static unsigned int get_id(struct nfq_data *tb)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    int id = 0;
    if (ph)
        id = ntohl(ph->packet_id);
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    unsigned char *packet;
    unsigned int id = get_id(nfa);
    unsigned int len = nfq_get_payload(nfa, &packet);

    if (check_host(packet, len))
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    else
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void MAKE_HASH(const char *file)
{
    std::ifstream input(file);
    std::string line;
    while (std::getline(input, line))
    {
        if (line.empty())
            continue;
        size_t comma = line.find(',');
        if (comma == std::string::npos)
            continue;
        std::string domain = line.substr(comma + 1);
        block.insert(domain);
    }
}

// main은 코드 그대로
int main(int argc, char **argv)
{
    if (argc not_eq 2)
    {
        printf("syntax : 1m-block <site list file>\n");
        printf("sample : 1m-block top-1m.txt\n");
        return -1;
    }
    MAKE_HASH(argv[1]);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;)
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS)
        {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}