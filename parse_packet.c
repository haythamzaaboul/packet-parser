#include "parse_packet.h"
#include <string.h> // memcpy

// ---- Helpers sûrs (pas de cast direct) ----
static inline int have(size_t need, size_t len, size_t off) {
    return off + need <= len;
}
static inline uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static inline uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static int is_ipv6_ext(uint8_t nh) {
    // RFC 8200 extension headers (liste non exhaustive, suffisant pour un parseur simple)
    switch (nh) {
        case 0:   // Hop-by-Hop Options
        case 43:  // Routing
        case 44:  // Fragment
        case 50:  // ESP
        case 51:  // AH
        case 60:  // Destination Options
            return 1;
        default:  return 0;
    }
}

// ---- Parse principal ----
pp_status parse_packet(const uint8_t *buf, size_t len, parsed_packet *out) {
    if (!buf || !out) return PP_MALFORMED;
    memset(out, 0, sizeof(*out));

    size_t off = 0;

    // ---- L2: Ethernet header ----
    if (!have(14, len, off)) return PP_TRUNCATED;
    memcpy(out->dst_mac, buf + off + 0, 6);
    memcpy(out->src_mac, buf + off + 6, 6);
    uint16_t ethertype = read_be16(buf + off + 12);
    off += 14;
    out->vlan_count = 0;

    // ---- VLAN(s) 802.1Q ----
    for (int i = 0; i < 2; ++i) {
        if (ethertype == 0x8100 || ethertype == 0x88A8) {
            // TCI (Tag Control Information) + EtherType
            if (!have(4, len, off)) return PP_TRUNCATED;
            uint16_t tci = read_be16(buf + off + 0);
            out->vlan_id[i] = tci & 0x0FFF;
            out->vlan_count++;
            ethertype = read_be16(buf + off + 2);
            off += 4;
        } else {
            break;
        }
    }

    out->ethertype = ethertype;
    out->l2_len = off;

    // ---- L3: IPv4 ou IPv6 ----
    if (ethertype == 0x0800) {
        // IPv4
        if (!have(20, len, off)) return PP_TRUNCATED;
        uint8_t vihl = buf[off + 0];
        uint8_t version = vihl >> 4;
        uint8_t ihl = (vihl & 0x0F) * 4; // en octets
        if (version != 4 || ihl < 20) return PP_MALFORMED;
        if (!have(ihl, len, off)) return PP_TRUNCATED;

        uint16_t total_len = read_be16(buf + off + 2);
        if (total_len < ihl) return PP_MALFORMED;//assurer que la longueur totale est au moins égale à IHL
        if (!have(total_len, len, off)) return PP_TRUNCATED;//vérifier que le paquet complet est disponible

        out->ip_ttl_hop = buf[off + 8];
        out->ip_proto   = buf[off + 9];
        memcpy(out->src_ip, buf + off + 12, 4);
        memcpy(out->dst_ip, buf + off + 16, 4);
        out->l3 = L3_IPV4;
        out->l3_len = ihl;

        out->ip_payload_len = (uint16_t)(total_len - ihl);
        out->l4_offset = off + ihl;

        off += ihl; // avancer à la charge utile L4

    } else if (ethertype == 0x86DD) {
        // IPv6 (header fixe 40 octets)
        if (!have(40, len, off)) return PP_TRUNCATED;
        uint8_t version = buf[off] >> 4;
        if (version != 6) return PP_MALFORMED;

        uint16_t payload_len = read_be16(buf + off + 4);
        if (!have(40 + payload_len, len, off)) return PP_TRUNCATED;

        uint8_t next_header = buf[off + 6];
        out->ip_ttl_hop = buf[off + 7]; // Hop Limit
        memcpy(out->src_ip, buf + off + 8, 16);
        memcpy(out->dst_ip, buf + off + 24, 16);
        out->l3 = L3_IPV6;

        size_t ip6_off = off;
        size_t nh_off = off + 40;
        size_t remaining = payload_len;
        out->l3_len = 40;

        uint8_t nh = next_header;
        out->ip_proto     = nh;
        out->ip_payload_len = (uint16_t)remaining;
        out->l4_offset    = nh_off;

        off = nh_off; // L4

    } else {
        return PP_UNSUPPORTED; // Pas IP
    }

    // ---- L4 ----
    out->l4 = L4_NONE;
    if (out->ip_payload_len == 0) return PP_OK; // pas de charge utile

    switch (out->ip_proto) {
        case 6: // TCP
            if (!have(20, len, off)) return PP_TRUNCATED;
            out->src_port = read_be16(buf + off + 0);
            out->dst_port = read_be16(buf + off + 2);
            {
                uint8_t data_offset = (buf[off + 12] >> 4) * 4;
                if (data_offset < 20) return PP_MALFORMED;
                if (!have(data_offset, len, off)) return PP_TRUNCATED;
                if (data_offset > out->ip_payload_len) return PP_MALFORMED;
                // Payload TCP = ip_payload_len - data_offset (si besoin)
            }
            out->l4 = L4_TCP;
            break;

        case 17: // UDP
            if (!have(8, len, off)) return PP_TRUNCATED;
            out->src_port = read_be16(buf + off + 0);
            out->dst_port = read_be16(buf + off + 2);
            // longueur UDP dispo en buf[off+4..5] si tu veux valider plus
            out->l4 = L4_UDP;
            break;

        case 1: // ICMPv4
            if (!have(4, len, off)) return PP_TRUNCATED;
            out->icmp_type = buf[off + 0];
            out->icmp_code = buf[off + 1];
            out->l4 = L4_ICMP;
            break;

        case 58: // ICMPv6
            if (!have(4, len, off)) return PP_TRUNCATED;
            out->icmp_type = buf[off + 0];
            out->icmp_code = buf[off + 1];
            out->l4 = L4_ICMPV6;
            break;

        default:
            // L4 non géré : on s’arrête proprement
            break;
    }

    return PP_OK;
}
