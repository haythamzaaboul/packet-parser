# packet_tracer — Minimal, Robust L2/L3/L4 Packet Parser (C)

A small, production-style parser for Ethernet → (VLAN) → IPv4/IPv6 → TCP/UDP/ICMP.  
Design goals: **safety**, **portability**, **clarity**—no packed-struct casts, full bounds checks, explicit big-endian reads.

---

## Features

- **Ethernet (L2)**: destination/src MAC, EtherType
- **VLAN**: supports 0/1/2 tags (802.1Q `0x8100`, 802.1ad `0x88A8`), extracts VID
- **IPv4**: validates Version/IHL/Total Length, exposes TTL, Protocol, src/dst IP
- **IPv6**: validates Version and Payload Length, exposes Hop Limit, Next Header, src/dst IP  
  - “No-extensions” mode by default; optionally reject known extension headers
- **L4**:
  - **TCP**: reads ports, validates Data Offset
  - **UDP**: reads ports (length optionally checked)
  - **ICMP/ICMPv6**: reads type/code
- **Defensive parsing**: length/offset guards, endian-safe reads, clear status codes

---

## Why this parser?

Typical pitfalls when parsing raw buffers in C:

- Casting to `struct` with `__attribute__((packed))` (alignment/UB/portability issues)
- Missing bounds checks → buffer overreads
- Endianness errors on multi-byte fields

This project avoids them by:
- **Never** casting buffer to protocol structs
- Using `have()` for **every** read
- Reading multi-byte fields with `read_be16/32`
- Returning precise error codes

---

## Project Layout

```
.
├── main.c              # Example driver / demo
├── parse_packet.h      # Public API
├── parse_packet.c      # Implementation
└── Makefile            # (optional) build helper
```

---

## Build

### Single command
```bash
gcc -std=c11 -Wall -Wextra -O2 main.c parse_packet.c -o packet_tracer
```

### With Makefile
```bash
make
./packet_tracer
```

---

## Quick Start

`main.c` contains a minimal Ethernet→IPv4→UDP example packet. Run:

```bash
./packet_tracer
```

Expected output (example):
```
L2: 66:77:88:99:aa:bb -> 00:11:22:33:44:55  EtherType=0x0800
IPv4: 192.0.2.1 -> 198.51.100.2  proto=17 ttl=64
L4: UDP 12345 -> 80
```

To parse **real captures**, replace the sample buffer with data from `recvfrom`, raw sockets, or `libpcap`, and pass the actual length to `parse_packet`.

---

## Public API

```c
// parse_packet.h
typedef enum {
    PP_OK = 0,
    PP_TRUNCATED,    // buffer shorter than required
    PP_UNSUPPORTED,  // protocol/feature not handled (e.g., IPv6 extensions)
    PP_MALFORMED     // inconsistent header fields/lengths
} pp_status;

typedef enum { L3_NONE=0, L3_IPV4, L3_IPV6 } l3_type;
typedef enum { L4_NONE=0, L4_TCP, L4_UDP, L4_ICMP, L4_ICMPV6 } l4_type;

typedef struct {
    // L2
    uint8_t  dst_mac[6], src_mac[6];
    uint16_t vlan_id[2];     // filled if vlan_count > 0
    int      vlan_count;     // 0..2
    uint16_t ethertype;

    // L3
    l3_type  l3;
    uint8_t  src_ip[16];     // IPv4 uses first 4 bytes
    uint8_t  dst_ip[16];
    uint8_t  ip_ttl_hop;     // TTL (v4) or Hop Limit (v6)
    uint8_t  ip_proto;       // v4 Protocol or v6 Next Header (final)
    uint16_t ip_payload_len; // bytes after IP header
    size_t   l2_len;         // bytes consumed at L2 (incl. VLAN)
    size_t   l3_len;         // IP header length (incl. v6 ext if enabled)
    size_t   l4_offset;      // absolute buffer offset of L4

    // L4
    l4_type  l4;
    uint16_t src_port, dst_port;
    uint8_t  icmp_type, icmp_code;
} parsed_packet;

pp_status parse_packet(const uint8_t *buf, size_t len, parsed_packet *out);
```

---

## Design Notes

- **Bounds safety**: `have(need,len,off)` guards every read; function returns early on truncation.
- **Endianness**: network fields are big-endian → use `read_be16/32` helpers.
- **No packed structs**: we copy exact bytes with `memcpy` and compose integers manually.
- **IPv6 extensions**: by default, either (a) **reject** known extension headers (`PP_UNSUPPORTED`) or (b) optionally **skip** them with a small walker (included in the fuller version). Choose the policy you prefer.
- **Network vs host order**: values in `parsed_packet` are stored as **raw bytes** (MAC/IP) and **host-order integers** where it makes sense (ports, lengths) for easier consumption.

---

## Error Handling

| Code            | Meaning                                                         | Typical cause                               |
|-----------------|-----------------------------------------------------------------|---------------------------------------------|
| `PP_OK`         | Parsed successfully                                             | —                                           |
| `PP_TRUNCATED`  | Buffer shorter than needed for current header                   | Capture short read / malformed frame        |
| `PP_UNSUPPORTED`| Valid but unsupported feature (e.g., IPv6 ext headers, non-IP) | Not implemented in this minimal parser      |
| `PP_MALFORMED`  | Fields inconsistent (IHL < 20, lengths mismatch, etc.)         | Corrupt packet / bogus header fields        |

---
