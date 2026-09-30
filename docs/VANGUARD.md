## Technical Specification: VANGUARD Internal Architecture

**Module:** Verified Addressing Node & Gateway for Unified Access, Registration & Devices (VANGUARD)

**Framework:** Perseo-Piscis Standard | DENSA Network

**Isolation Model:** Dual-Node Split Plane (External Plane / Internal Plane)

---

### 1. Dual System Topology

VANGUARD physically decouples the external exposure plane from the internal control plane. There is no single point that simultaneously concentrates local key/lease management and direct WAN egress.

```text
               +-------------------------------------------+
               |             PUBLIC INTERNET               |
               +-------------------------------------------+
                                     ^
                                     | Native IPv6 / WAN Traffic
                                     v
               +-------------------------------------------+
               |            VANGUARD-OUT (V-OUT)           |
               |         [Perimeter Node / Gateway]        |
               |  - Encrypted DNS Resolution (Cloudflare)  |
               |  - L3/L4 Sanitization & Scrubbing         |
               |  - Default Gateway (::/0)                 |
               +-------------------------------------------+
                                     ^
                                     | Dedicated Inter-Core Link
                                     | (Coordinates X=0, Y=1 <-> Y=2)
                                     v
+--------------------+         +-------------------------------------------+
|    DENSA NODES     |<------->|            VANGUARD-IN (V-IN)             |
| (Laptops, Phones,  |  DCLP/  |         [Local Intranet Manager]          |
|  Video Servers)    |  DDRP   |  - DDRP Server (Binary Handshake)         |
+--------------------+         |  - LCoord and IPv6 Allocator/Revoker      |
                               |  - Airtime and Traffic Monitoring         |
                               |  - Network Report Generator               |
                               +-------------------------------------------+

```

---

### 2. Node 1: VANGUARD-OUT (V-OUT) — The Perimeter Bastion

Its sole responsibility is to shield Internet access and scrub outbound and inbound traffic from the WAN toward the intranet.

- **IPv6 Address in DENSA:** `fd00:de00:0:0::1/128` (Coordinates `X=0, Y=1`).

- **Main Functions:**

1. **Upstream DNS Resolution (Cloudflare):**

- Channels all DNS requests through DNS-over-TLS (DoT) or DNS-over-HTTPS (DoH) toward `2606:4700:4700::1111` and `2606:4700:4700::1001`.
- Blocks cleartext outbound DNS queries (UDP/TCP port 53) originating from any other node to prevent metadata leaks (_DNS leak_).

2. **Packet Sanitization and Scrubbing:**

- **MTU/MSS clamping validation:** Limits IPv6 fragment size to avoid silent drops due to broken Path MTU Discovery on ISP networks.
- **Anti-Spoofing (BCP 38 / uRPF):** Immediately discards outbound packets whose source address does not match the range of authorized clients reported by V-IN.
- **DoS/Flooding Mitigation:** Rate-limiting of SYN and UDP packets per second to prevent a compromised device from drowning the Telmex link.

3. **Default Route:**

- Acts as the _Default Gateway_ announced in DDRP for devices with egress privileges (`flags & 0x01`).

---

### 3. Node 2: VANGUARD-IN (V-IN) — The Bouncer and Local Auditor

It is the guardian of the internal DENSA network. It has no direct exposure to the Internet egress interface and operates exclusively toward the LAN and the link with V-OUT.

- **IPv6 Address in DENSA:** `fd00:de00:0:0::2/128` (Coordinates `X=0, Y=2`).

- **Main Functions:**

1. **Binary DDRP Server (Control Plane):**

- Listens for `DDRP_PKT_SOLICIT` requests on the assigned UDP port.
- Validates the signature/HMAC of access tokens and reserves the `(X, Y)` coordinate corresponding to the device type.

- Configures the local WireGuard interface and injects the Curve25519 public key with its `AllowedIPs = fd00:de00:X:0::Y/128`.

2. **Atomic Revocation Cycle:**

- If a device fails to send its `DCLP_MSG_BEAT` keepalive or its lease expires (`lease_seconds`), V-IN:
- Removes the WireGuard peer immediately (`wg set wg0 peer <KEY> remove`).
- Emits a purge instruction toward V-OUT through the inter-core channel to invalidate any active flow toward the Internet.

3. **Traffic and Airtime Monitoring:**

- Measures the continuous packet consumption of each node to detect radio saturation or local loops on Wi-Fi.
- Monitors TCP/UDP retransmission metrics to alert on signal degradation before a video stream suffers micro-cuts.

4. **Report Engine:**

- Periodically generates consolidated statistics: active devices per quadrant `X`, transmitted/received volume (TX/RX), consumption peaks, and bouncer blocking events (unauthorized connection attempts between `X=3` and `X=2` devices).

---

### 4. Inter-Core Control Channel (V-IN $\longleftrightarrow$ V-OUT)

To maintain coherence without sharing heavy databases, the two nodes synchronize through an ultra-lightweight internal UDP socket using the DCLP protocol:

- **Active Route Table Synchronization:** Each time V-IN approves a lease with Internet egress, it notifies V-OUT:

```text
[V-IN] -- (SYNC_ADD: IPv6=fd00:de00:3:0::5, PubKey=...) --> [V-OUT]

```

V-OUT adds that IP to its allowed set in `nftables`. If it is not in that set, the incoming packet at V-OUT is silently discarded (`DROP`).

- **Forced Cut Instruction:** When V-IN revokes or disconnects a device:

```text
[V-IN] -- (SYNC_DEL: IPv6=fd00:de00:3:0::5) -------------> [V-OUT]

```

V-OUT instantly purges the associated conntrack sessions, cutting any ongoing Internet connection.

---

### 5. Complete Operational Flow Summary

1. The phone or laptop sends a DDRP binary packet to **V-IN** requesting entry.
2. **V-IN** evaluates validity, assigns the `(X, Y)` pair, computes the IPv6, and activates the local tunnel.

3. If the device has WAN egress, **V-IN** notifies **V-OUT** to accept routing for that IP.
4. The device speaks directly in P2P with the video server inside the local network without the traffic saturating the home modem's CPU.
5. When the device queries a web page or external service, its packets travel encrypted toward **V-OUT**, which cleans the headers, resolves the domain via encrypted DNS at Cloudflare, and sends the data to the Internet transparently.
