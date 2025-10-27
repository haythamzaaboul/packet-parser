# packet_tracer — Minimal, Robust L2/L3/L4 Packet Parser (C)

A small, production-style parser for Ethernet → (VLAN) → IPv4/IPv6 → TCP/UDP/ICMP.
Design goals: safety, portability, clarity—no packed-struct casts, full bounds checks, explicit big-endian reads.

Features

Ethernet (L2): destination/src MAC, EtherType

VLAN: supports 0/1/2 tags (802.1Q 0x8100, 802.1ad 0x88A8), extracts VID

IPv4: validates Version/IHL/Total Length, exposes TTL, Protocol, src/dst IP

IPv6: validates Version and Payload Length, exposes Hop Limit, Next Header, src/dst IP

“No-extensions” mode by default; optionally reject known extension headers

L4:

TCP: reads ports, validates Data Offset

UDP: reads ports (length optionally checked)

ICMP/ICMPv6: reads type/code

Defensive parsing: length/offset guards, endian-safe reads, clear status codes

Why this parser?

Typical pitfalls when parsing raw buffers in C:

Casting to struct with __attribute__((packed)) (alignment/UB/portability issues)

Missing bounds checks → buffer overreads

Endianness errors on multi-byte fields

This project avoids them by:

Never casting buffer to protocol structs

Using have() for every read

Reading multi-byte fields with read_be16/32

Returning precise error codes

Project Layout
.
├── main.c              # Example driver / demo
├── parse_packet.h      # Public API
├── parse_packet.c      # Implementation
└── Makefile            # (optional) build helper

Build
Single command
gcc -std=c11 -Wall -Wextra -O2 main.c parse_packet.c -o packet_tracer

With Makefile
make
./packet_tracer
