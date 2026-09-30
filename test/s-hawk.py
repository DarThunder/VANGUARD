import hashlib
import hmac
import ipaddress
import secrets
import socket
import struct
import time

VOUT_PORT = 1025
TOKEN_HEX = "1c28da1b1a0d497290486157ce941ccd76a503e9188f0e7b1893a11c703e15af"
enrollment_token = bytes.fromhex(TOKEN_HEX)

token_hash = hashlib.sha256(enrollment_token).digest()

c_sock = socket.socket(socket.AddressFamily.AF_INET6, socket.SOCK_DGRAM)
c_sock.bind(("::1", 0))
c_sock.settimeout(2.0)

FMT_SOLICIT = "!BBBH32s32s32s"
FMT_CHALLENGE = "!B32sI"
FMT_RESOLVE = "!BI32sB32s"
FMT_ASSIGN = "!BIII16s32sHI"

t_start = time.perf_counter()

client_pk = secrets.token_bytes(32)
hostname = b"workstation-01\x00".ljust(32, b"\x00")
solicit_raw = struct.pack(
    FMT_SOLICIT,
    0x01,
    0x02,
    0x01,
    51822,
    client_pk,
    token_hash,
    hostname,
)

c_sock.sendto(solicit_raw, ("::1", VOUT_PORT))

data, _ = c_sock.recvfrom(2048)
pkt_type = data[0]
if pkt_type == 0x0E:
    print("[CLI] Registro rechazado por VANGUARD en el Paso 1.")
    exit(1)

_, nonce, challenge_id = struct.unpack(FMT_CHALLENGE, data[:37])

proof = hmac.new(enrollment_token, nonce, hashlib.sha256).digest()
resolve_raw = struct.pack(
    FMT_RESOLVE,
    0x03,
    challenge_id,
    proof,
    0x02,
    client_pk,
)

c_sock.sendto(resolve_raw, ("::1", VOUT_PORT))

data, _ = c_sock.recvfrom(2048)
t_end = time.perf_counter()

if data[0] == 0x0E:
    print("[CLI] Registro rechazado por HMAC inválido.")
    exit(1)

_, cid, x, y, raw_ipv6, gw_pk, gw_port, lease = struct.unpack(
    FMT_ASSIGN, data[:67]
)
assigned_ip = ipaddress.IPv6Address(raw_ipv6)

print("[CLI] ¡Handshake DDRP binario completado con éxito!")
print(f"  * Challenge ID:     {cid}")
print(f"  * Coordenadas:      X={x}, Y={y}")
print(f"  * IPv6 Asignada:    {assigned_ip}")
print(f"  * WireGuard GW:     Puerto {gw_port}, PK: {gw_pk.hex()[:16]}...")
print(f"  * RTT Total:        {(t_end - t_start) * 1000:.3f} ms")