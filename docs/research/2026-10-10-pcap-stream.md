# Capture stream provenance

Read the libpcap primary-source savefile manual:
https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap-savefile.manfile.in

The manual documents header sizes, byte orders, timestamp precisions, snapshot truncation and link-layer metadata. It recommends using libpcap rather than a custom decoder for broad format support. WiFiSecLab's current Python implementation is deliberately restricted to the classic radiotap format already emitted by its collector; it is not a general libpcap replacement. Strict snapshot rejection protects protocol evidence from incomplete packets.

New code supports append-only incremental consumption and exposes pending tails separately from complete records. Full suite: 166 tests passed on 2026-10-10. Historical capture comparison is recorded separately. No new 802.11 normative clause or vulnerability paper was completed in this increment; the wider reading objectives remain active.
