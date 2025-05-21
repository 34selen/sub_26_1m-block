#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <linux/types.h>

#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string>
#include <unordered_set>
#include <iostream>
#include <fstream>

std::string http_methods[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
std::unordered_set<std::string> block_list;

std::string extract_host(const char *data, unsigned int len)
{
    for (unsigned int i = 0; i + 5 < len; ++i)
    {
        if (strncmp(data + i, "Host:", 5) == 0)
        {
            const char *ptr = data + i + 5;
            if (*ptr == ' ')
                ++ptr;
            std::string host;
            while (*ptr != '\r' && (ptr - data) < (int)len)
            {
                host += *ptr++;
            }
            return host;
        }
    }
    return "";
}

bool should_block(unsigned char *pkt, unsigned int len)
{
    auto *ip = (struct libnet_ipv4_hdr *)pkt;
    if (ip->ip_p != IPPROTO_TCP)
        return false;

    auto *tcp = (struct libnet_tcp_hdr *)(pkt + ip->ip_hl * 4);
    const char *payload = (const char *)(pkt + ip->ip_hl * 4 + tcp->th_off * 4);

    uint16_t src_port = ntohs(tcp->th_sport);
    uint16_t dst_port = ntohs(tcp->th_dport);
    if (src_port != 80 && dst_port != 80)
        return false;

    bool is_http = false;
    for (const auto &m : http_methods)
    {
        if (strncmp(payload, m.c_str(), m.size()) == 0)
        {
            is_http = true;
            break;
        }
    }
    if (!is_http)
        return false;

    std::string host = extract_host(payload, len);
    if (block_list.count(host))
    {
        printf("[+] Blocked domain: %s\n", host.c_str());
        return true;
    }

    return false;
}

uint32_t fetch_packet_id(struct nfq_data *nfa)
{
    struct nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfa);
    if (!hdr)
        return 0;
    return ntohl(hdr->packet_id);
}

int packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data)
{
    unsigned char *buf = nullptr;
    uint32_t pkt_id = fetch_packet_id(nfa);
    int pkt_len = nfq_get_payload(nfa, &buf);

    if (should_block(buf, pkt_len))
        return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, nullptr);
    else
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
}

void load_blocklist(const char *filename)
{
    std::ifstream infile(filename);
    std::string line;
    while (std::getline(infile, line))
    {
        if (line.empty())
            continue;
        size_t pos = line.find(',');
        if (pos == std::string::npos)
            continue;
        std::string domain = line.substr(pos + 1);
        block_list.insert(domain);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <csv_file>\n", argv[0]);
        return 1;
    }

    load_blocklist(argv[1]);

    struct nfq_handle *handle = nfq_open();
    if (!handle)
    {
        perror("nfq_open");
        exit(EXIT_FAILURE);
    }

    if (nfq_unbind_pf(handle, AF_INET) < 0)
    {
        perror("nfq_unbind_pf");
        exit(EXIT_FAILURE);
    }

    if (nfq_bind_pf(handle, AF_INET) < 0)
    {
        perror("nfq_bind_pf");
        exit(EXIT_FAILURE);
    }

    struct nfq_q_handle *queue = nfq_create_queue(handle, 0, &packet_handler, nullptr);
    if (!queue)
    {
        perror("nfq_create_queue");
        exit(EXIT_FAILURE);
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        perror("nfq_set_mode");
        exit(EXIT_FAILURE);
    }

    int fd = nfq_fd(handle);
    char buf[4096] __attribute__((aligned));
    int received;

    while ((received = recv(fd, buf, sizeof(buf), 0)) && received >= 0)
    {
        nfq_handle_packet(handle, buf, received);
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);

    return 0;
}
