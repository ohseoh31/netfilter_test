struct ether_h
{
  unsigned char ether_dst_mac[6];  /*dst_mac 6byte*/
  unsigned char ether_src_mac[6];  /*src_mac 6byte*/  
  unsigned short ether_type; //2byte
};


struct ip_hdr
{
    unsigned int ip_hl:4;   /* header length */
    unsigned int ip_v:4;    /* version */
    u_int8_t ip_tos;        /* type of service */
    u_short ip_len;         /* total length */
    u_short ip_id;          /* identification */
    u_short ip_off;         /* fragment offset field */
    u_int8_t ip_ttl;        /* time to live */
    u_int8_t ip_p;          /* protocol */
    u_short ip_sum;         /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst;
 };


struct tcp_hdr
{
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    tcp_seq th_seq;         /* sequence number */
    tcp_seq th_ack;         /* acknowledgement number */
    u_int8_t th_x2:4;       /* (unused) */
    u_int8_t th_off:4;      /* data offset */
    u_int8_t th_flags;      
    u_int16_t th_win;       /* window */
    u_int16_t th_check;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */
};


void printIP_Info (struct ip_hdr *ip_h)
{
    char *someTest;
    // IP 헤더에서 데이타 정보를 출력한다.
    printf("    ---------------------------------------------------------\n");
    printf("    IP 패킷\n");
    printf("    Version     : %d(0x%02x)\n", ip_h->ip_v, ip_h->ip_v);
    printf("    Header Len  : %d(0x%02x)\n", ip_h->ip_hl, ip_h->ip_hl);
    printf("    Ident       : %d(0x%02x)\n", ntohs(ip_h->ip_id), ntohs(ip_h->ip_id));
    printf("    TTL         : %d(0x%02x)\n", ip_h->ip_ttl, ip_h->ip_ttl); 
    printf("    Src Address : %s\n", inet_ntoa(ip_h->ip_src));
    //printf("    Src Address : %ld\n", ip_h->ip_src.s_addr);

//printf("%02x ", buf[i]

    //printf("    Dst Address : %s\n", inet_ntoa(ip_h->ip_dst));
    printf("    IP PROTOCOL : %d(0x%02x)\n", ip_h->ip_p, ip_h->ip_p);
    printf("    ---------------------------------------------------------\n");
}

void printTCP_Info(struct tcp_hdr *tcp_h) //TCP 20byt info Not Optional Header
{
    printf("        ---------------------------------------------------------\n");
    printf("        TCP 패킷\n");
    printf("        Src Port    : %d(0x%04x)\n" , ntohs(tcp_h->th_sport), ntohs(tcp_h->th_sport));
    printf("        Dst Port    : %d(0x%04x)\n" , ntohs(tcp_h->th_dport), ntohs(tcp_h->th_dport));
    printf("        seq Numb    : %d(0x%08x)\n" , ntohl(tcp_h->th_seq), ntohl(tcp_h->th_seq));
    printf("        ack Numb    : %d(0x%08x)\n" , ntohl(tcp_h->th_ack), ntohl(tcp_h->th_ack));
    //printf("      Version     : %02x\n", tcp_h->th_x2);
    printf("        Header Len  : %d(0x%02x)\n", (tcp_h->th_off*4), (tcp_h->th_off*4)); //x4 value is length
    printf("        ---------------------------------------------------------\n");
}