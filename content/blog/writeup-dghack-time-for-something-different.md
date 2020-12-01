---
title: "Writeup DG'hAck: Time for Something Different"
date: 2020-11-30T17:03:31+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

This is a steganography challenge where we're given a PCAP file. Opening it in wireshark reveals a list of identical ICMP packets.

Nothing seems to be unique, except the time of each packet, that we can extract using `tshark`:

```bash
$ tshark -r data.pcap -T fields -e frame.time_epoch
1604485685.271523000
1604485685.974534000
1604485686.737381000
1604485687.390550000
1604485688.103364000
1604485689.336651000
1604485690.500205000
1604485690.982931000
1604485691.465408000
1604485692.617796000
1604485693.701056000
1604485694.814156000
1604485695.686772000
1604485696.799993000
1604485697.943153000
1604485699.106441000
1604485699.589015000
1604485700.071611000
1604485700.754520000
1604485701.266580000
1604485702.449633000
1604485702.942506000
1604485704.054744000
1604485705.228047000
1604485705.589787000
1604485706.843252000
```

... there isn't anything that stands out. We could also look at the time delta in between each packet:

```bash
$ tshark -r data.pcap -T fields -e frame.time_delta
0.000000000
0.703011000
0.762847000
0.653169000
0.712814000
1.233287000
1.163554000
0.482726000
0.482477000
1.152388000
1.083260000
1.113100000
0.872616000
1.113221000
1.143160000
1.163288000
0.482574000
0.482596000
0.682909000
0.512060000
1.183053000
0.492873000
1.112238000
1.173303000
0.361740000
1.253465000
```

Hmm.. The first bit looks like binary, but decoding it gives nothing useful. Looking at the second and third lines, the deltas start with `70` and `76`, which are the ASCII codes for `F` and `L`.

This is it, the first three chars without the dot represent ASCII codes, let's decode them:

```bash
$ tshark -r data.pcap -T fields -e frame.time_delta | python -c 'import sys; print("".join(map(lambda d: chr(int(d.replace(".", "")[:3])), sys.stdin)))'
FLAG{t00sloWort00D3v1ou$}
```

The flag is `t00sloWort00D3v1ou$`.

---

[View all of the DG'hAck articles](/tags/dghack).
