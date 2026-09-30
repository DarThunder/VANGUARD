## DENSA Ecosystem Standard (v1.0)

**Full Name:** iDar Ecosystem Network Service Alliance (DENSA)

**Reference Framework:** Perseo-Piscis Standard

**Status:** Normative Ecosystem Specification

---

### 1. Purpose and Scope of the Standard

The **DENSA** standard does not describe cables, sockets, or physical ports. It is the normative specification that defines how services and identities are organized, federated, discovered, and governed within a sovereign network under Perseo-Piscis.

It establishes the Zero-Trust framework, the taxonomy of participating nodes, the service lifecycle, and the interoperability contract that any implementation (such as VANGUARD) must guarantee.

```text
+---------------------------------------------------------------+
|                       DENSA STANDARD                          |
|                                                               |
|  1. Philosophy & Foundational Principles                      |
|  2. Taxonomy of Clusters and Roles                            |
|  3. Identity and Service Lifecycle                            |
|  4. Normative Inter-Cluster Access Matrix                     |
|  5. Service Discovery Contract (DENSA Registry)               |
+---------------------------------------------------------------+

```

---

### 2. Foundational Principles of DENSA

1. **Data and Link Sovereignty:** No service dependent on DENSA may make its local availability contingent upon the existence of a connection to external providers or public cloud services.
2. **Role Immutability:** A node cannot self-assign privileges or alter its role within the ecosystem; its quadrant and operational capabilities are bound to its formal enrollment process.
3. **Minimum Transit Privilege:** Membership in the alliance does not grant total visibility. Services are isolated by default and can only communicate through explicit transit contracts.
4. **Agony of Underlying Infrastructure:** DENSA operates identically regardless of whether the physical transport is fiber, Ethernet, congested Wi-Fi, or ad-hoc links, delegating channel stability to the transport and link protocols (DCLP).

---

### 3. Taxonomy of Nodes and Clusters

DENSA classifies all its members within standardized functional clusters, logically represented by the functional quadrant $X$ of the network:

| Cluster                        | Designation                     | Definition and Scope                                                                                   | Normative Restrictions                                                                     |
| ------------------------------ | ------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| **`CLUSTER_CORE`** (`X=0`)     | **Governance Core**             | Nodes that run the VANGUARD control plane (V-IN / V-OUT), name resolution, and perimeter sanitization. | Prohibited from hosting end-user services or mass storage.                                 |
| **`CLUSTER_INFRA`** (`X=1`)    | **Services and Infrastructure** | Dedicated compute servers, transcoding, video streaming, databases, and microservices.                 | Outbound WAN traffic blocked by default; only serve requests from authorized nodes.        |
| **`CLUSTER_DEV`** (`X=2`)      | **Workstations**                | Laptops and development stations managed by alliance operators.                                        | Unrestricted administration access over `INFRA` and full WAN egress.                       |
| **`CLUSTER_CONSUMER`** (`X=3`) | **Consumer Clients**            | Smartphones, tablets, and multimedia players dedicated to consuming content.                           | Traffic strictly restricted to published service ports; isolation between each other.      |
| **`CLUSTER_EDGE`** (`X=4`)     | **Peripherals and Telemetry**   | Sensors, microcontrollers, and low-power embedded devices.                                             | May only emit metrics or receive commands from `CORE` or `INFRA`.                          |
| **`CLUSTER_GUEST`** (`X=99`)   | **Foreign Nodes**               | Devices in quarantine or temporary guests without verified membership.                                 | Internal traffic to any other cluster denied at 100%; only transit toward the WAN Gateway. |

---

### 4. Normative Inter-Cluster Transit Matrix

Any implementation of the control plane must enforce the following communication matrix between alliance clusters:

```text
DESTINATION --->
SOURCE      CORE (0)    INFRA (1)   DEV (2)    CONSUMER (3)   EDGE (4)    WAN (OUT)
CORE (0)       [YES]       [YES]      [YES]        [YES]        [YES]       [YES]
INFRA (1)     [SYNC]       [YES]     [RESP]       [RESP]       [CMD]       [RULE]
DEV (2)        [YES]       [YES]      [YES]        [YES]        [YES]       [YES]
CONSUMER (3)  [AUTH]     [ACCESS]   [BLOCK]      [BLOCK]      [BLOCK]      [YES]
EDGE (4)      [AUTH]     [METRIC]   [BLOCK]      [BLOCK]      [BLOCK]     [BLOCK]
GUEST (99)    [AUTH]     [BLOCK]    [BLOCK]      [BLOCK]      [BLOCK]      [YES]

Legend:
- [YES]: Bidirectional connection allowed.
- [ACCESS]: Only allowed toward registered service ports (e.g. video/streaming).
- [RESP]: Only responses to previously initiated connections (stateful).
- [CMD]: Only command emission toward perimeter devices.
- [METRIC]: Only unidirectional telemetry.
- [AUTH/SYNC]: Traffic exclusive to internal control signaling.
- [RULE]: WAN egress restricted only via explicit whitelist.
- [BLOCK]: Immediate packet discard (silent DROP).

```

---

### 5. Service Publication and Discovery Standard (DENSA Registry)

To avoid the fragility of broadcast/multicast services on wireless networks, DENSA defines a deterministic registration model:

1. **Canonical Naming:**
   Services within the alliance are addressed through the reserved namespace `.densa`:

```text
<service>.<cluster-subdomain>.densa

```

- _Video example:_ `stream.infra.densa` $\to$ Resolves to coordinate `fd00:de00:1:0::Y`.
- _Dev panel example:_ `metrics.core.densa` $\to$ Resolves to `fd00:de00:0:0::2`.

2. **Service Descriptor (Service Manifest):**
   Every service mounted on the `INFRA` cluster that must be visible to `CONSUMER` must report its operational manifest to V-IN:

- **Service Name:** Unique identifier (ASCII).
- **Target LCoord:** `(X, Y)` coordinates of the container or node hosting it.
- **Allowed Ports:** TCP/UDP ports authorized to receive traffic.
- **Auth Level:** Token level required for a client to obtain DNS resolution.

---

### 6. Compliance and Certification of Implementations

For a component or software to be certified as **"DENSA Compatible"**:

- It must interact with the network exclusively through cryptographic primitives compatible with Curve25519.
- It must implement the **DDRP** protocol to request, renew, or revoke credentials before VANGUARD.
- It must encapsulate its control and telemetry traffic using the binary wire-format of the **DCLP** protocol.
- It must tolerate complete network partitions (WAN Internet outage) without aborting local inter-node operation.
