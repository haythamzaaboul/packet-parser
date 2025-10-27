#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PP_OK = 0,
    PP_TRUNCATED,      // paquet tronqué / longueur insuffisante
    PP_UNSUPPORTED,    // protocole non géré (ex: EtherType inconnu)
    PP_MALFORMED       // champs incohérents (longueurs, IHL, etc.)
} pp_status;

typedef enum { L3_NONE=0, L3_IPV4, L3_IPV6 } l3_type;
typedef enum { L4_NONE=0, L4_TCP, L4_UDP, L4_ICMP, L4_ICMPV6 } l4_type;

typedef struct {
    // L2
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t vlan_id[2];   // 0 si absent; second pour Q-in-Q
    int      vlan_count;   // 0,1,2
    uint16_t ethertype;    // EtherType final après VLAN(s)

    // L3
    l3_type  l3;
    uint8_t  src_ip[16];   // IPv4 sur 4 octets (début), IPv6 sur 16
    uint8_t  dst_ip[16];
    uint8_t  ip_ttl_hop;   // TTL (v4) ou Hop Limit (v6)
    uint8_t  ip_proto;     // v4: Protocol, v6: Next Header final
    uint16_t ip_payload_len; // longueur utile L4 (après en-tête IP)

    // L4
    l4_type  l4;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  icmp_type;    // v4 ou v6
    uint8_t  icmp_code;

    // Offsets utiles
    size_t   l2_len;       // bytes consommés pour L2 (14 + VLANs)
    size_t   l3_len;       // longueur de l'en-tête IP
    size_t   l4_offset;    // offset absolu du début L4 dans le buffer
} parsed_packet;

pp_status parse_packet(const uint8_t *buf, size_t len, parsed_packet *out);

#ifdef __cplusplus
}
#endif
