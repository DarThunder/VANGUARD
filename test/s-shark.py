import base64
import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import subprocess
import time
from nacl.public import PrivateKey

VOUT_HOST = "::1"
VOUT_PORT = 1025

try:
    with open("vanguard_master.key", "rb") as f:
        master_token = f.read(32)
except FileNotFoundError:
    print("[ERROR] No se encontró vanguard_master.key en el directorio.")
    exit(1)

token_hash = hashlib.sha256(master_token).digest()

client_sk = PrivateKey.generate()
client_pk_bytes = bytes(client_sk.public_key)
client_sk_b64 = base64.b64encode(bytes(client_sk)).decode("utf-8")
client_pk_b64 = base64.b64encode(client_pk_bytes).decode("utf-8")

print(f"[CLI] Clave WireGuard del cliente (Base64): {client_pk_b64}")

FMT_SOLICIT = "!BBBH32s32s32s"
FMT_CHALLENGE = "!B32sI"
FMT_RESOLVE = "!BI32sB32s"
FMT_ASSIGN = "!BIII16s32sHI"

sock = socket.socket(socket.AddressFamily.AF_INET6, socket.SOCK_DGRAM)
sock.bind(("::1", 0))
sock.settimeout(2.0)

hostname = b"workstation-real\x00".ljust(32, b"\x00")
solicit_raw = struct.pack(
    FMT_SOLICIT,
    0x01,
    0x02,
    0x01,
    51822,
    client_pk_bytes,
    token_hash,
    hostname,
)

t0 = time.perf_counter()
sock.sendto(solicit_raw, (VOUT_HOST, VOUT_PORT))

data, _ = sock.recvfrom(2048)
if data[0] == 0x0E:
    print("[CLI] SOLICIT rechazado.")
    exit(1)

_, nonce, cid = struct.unpack(FMT_CHALLENGE, data[:37])

proof = hmac.new(master_token, nonce, hashlib.sha256).digest()
resolve_raw = struct.pack(
    FMT_RESOLVE, 0x03, cid, proof, 0x02, client_pk_bytes
)
sock.sendto(resolve_raw, (VOUT_HOST, VOUT_PORT))

data, _ = sock.recvfrom(2048)
t1 = time.perf_counter()

if data[0] == 0x0E:
    print("[CLI] RESOLVE rechazado.")
    exit(1)

_, cid, x, y, raw_ipv6, gw_pk_bytes, gw_port, lease = struct.unpack(
    FMT_ASSIGN, data[:67]
)
assigned_ip = ipaddress.IPv6Address(raw_ipv6)
gw_pk_b64 = base64.b64encode(gw_pk_bytes).decode("utf-8")

print(f"\n[CLI] Handshake completado en {(t1 - t0)*1000:.3f} ms:")
print(f"  * IPv6 asignada:   {assigned_ip}")
print(f"  * Gateway WG Port: {gw_port}")
print(f"  * Gateway WG PK:   {gw_pk_b64}")
print(f"  * Lease:           {lease} segundos\n")

IFACE = "wg-test-cli"
GW_IP = f"fd00:de00:0:{x}::1"

print("[CLI] Levantando interfaz WireGuard local...")
subprocess.run(
    f"ip link del dev {IFACE} 2>/dev/null", shell=True, check=False
)

subprocess.run(
    f"ip link add dev {IFACE} type wireguard", shell=True, check=True
)
with open("/tmp/cli_wg.key", "w") as f:
    f.write(client_sk_b64 + "\n")

subprocess.run(
    f"wg set {IFACE} listen-port 51899 private-key /tmp/cli_wg.key peer {gw_pk_b64} allowed-ips fd00:de00::/32 endpoint [::1]:{gw_port}",
    shell=True,
    check=True,
)
os.remove("/tmp/cli_wg.key")

subprocess.run(
    f"ip address add {assigned_ip}/64 dev {IFACE}", shell=True, check=True
)
subprocess.run(f"ip link set dev {IFACE} up", shell=True, check=True)

print(f"\n[CLI] Probando conectividad con el Gateway ({GW_IP}) vía ping6:")
ping_cmd = f"ping -6 -c 3 -I {IFACE} {GW_IP}"
subprocess.run(ping_cmd, shell=True)

print(
    f"\n[CLI] Esperando {lease + 2} segundos para probar la expiración del lease..."
)
time.sleep(lease + 2)

print("\n[CLI] Probando ping6 tras vencimiento de lease (debe fallar):")
res = subprocess.run(
    f"ping -6 -c 2 -W 1 -I {IFACE} {GW_IP}", shell=True, check=False
)

if res.returncode != 0:
    print(
        "\n>>> ÉXITO: El tráfico se bloqueó porque VANGUARD expulsó al peer del kernel."
    )
else:
    print(
        "\n>>> ALERTA: El peer sigue transmitiendo, revisar el garbage collector."
    )

subprocess.run(f"ip link del dev {IFACE}", shell=True, check=False)