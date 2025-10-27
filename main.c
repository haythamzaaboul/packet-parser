// main.c
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "parse_packet.h"

static void print_mac(const uint8_t m[6]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
}
static void print_ip4(const uint8_t a[4]) {
    printf("%u.%u.%u.%u", a[0],a[1],a[2],a[3]);
}
static const char* st2str(pp_status s){
    switch(s){
        case PP_OK: return "OK";
        case PP_TRUNCATED: return "TRUNCATED";
        case PP_UNSUPPORTED: return "UNSUPPORTED";
        case PP_MALFORMED: return "MALFORMED";
        default: return "?";
    }
}

int main(void) {
    // Ethernet (14) + IPv4 (20) + UDP (8) + payload "ABCD" (4) = 46 bytes
    static const uint8_t pkt[] = {
        // --- Ethernet ---
        0x00,0x11,0x22,0x33,0x44,0x55,        // dst MAC
        0x66,0x77,0x88,0x99,0xaa,0xbb,        // src MAC
        0x08,0x00,                            // EtherType IPv4

        // --- IPv4 header (minimal, IHL=20) ---
        0x45,0x00,                            // Version/IHL=4/5, DSCP=0
        0x00,0x20,                            // Total Length = 32 (20 IP + 8 UDP + 4 data)
        0x00,0x00,                            // Identification
        0x00,0x00,                            // Flags/Fragment
        0x40,                                 // TTL = 64
        0x11,                                 // Protocol = 17 (UDP)
        0x00,0x00,                            // Header checksum (0 pour ce test)
        0xC0,0x00,0x02,0x01,                  // Src IP = 192.0.2.1
        0xC6,0x33,0x64,0x02,                  // Dst IP = 198.51.100.2

        // --- UDP header ---
        0x30,0x39,                            // Src port = 12345
        0x00,0x50,                            // Dst port = 80
        0x00,0x0C,                            // Length = 12 (8 header + 4 data)
        0x00,0x00,                            // Checksum (0 pour ce test)

        // --- Payload (4 bytes) ---
        0x41,0x42,0x43,0x44                   // "ABCD"
    };
    const size_t len = sizeof(pkt);

    parsed_packet p;
    pp_status st = parse_packet(pkt, len, &p);
    if (st != PP_OK) {
        printf("parse error: %d (%s)\n", st, st2str(st));
        return 1;
    }

    printf("L2: ");
    print_mac(p.src_mac); printf(" -> "); print_mac(p.dst_mac);
    printf("  EtherType=0x%04x", p.ethertype);
    if (p.vlan_count) {
        printf("  VLANs=");
        for (int i=0;i<p.vlan_count;i++) printf("%s%u", i?"/":"", p.vlan_id[i]);
    }
    printf("\n");

    if (p.l3 == L3_IPV4) {
        printf("IPv4: "); print_ip4(p.src_ip); printf(" -> "); print_ip4(p.dst_ip);
        printf("  proto=%u ttl=%u\n", p.ip_proto, p.ip_ttl_hop);
    }

    if (p.l4 == L4_UDP) {
        printf("UDP %u -> %u  (L4 offset=%zu)\n", p.src_port, p.dst_port, p.l4_offset);
    }

    return 0;
}
