import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import struct
import threading
import time

VOUT_PORT = 1025
secret = str(secrets.randbelow(0xFFFFFFFF)).encode()

def vanguard_out():
    v_sock = socket.socket(socket.AddressFamily.AF_INET6, socket.SOCK_DGRAM)
    v_sock.bind(("::1", VOUT_PORT, 0, 0))

    pre_registry = {}
    registry = {}
    print("[VOUT] Centinela activo y escuchando en puerto", VOUT_PORT)

    while True:
        data, addr = v_sock.recvfrom(2048)
        msg = json.loads(data.decode("utf-8"))
        msg_type = msg.get("message_type")

        if msg_type == 0x01:
            if (
                bytes.fromhex(msg.get("hash_token"))
                != hashlib.sha256(secret).digest()
            ):
                v_sock.sendto(
                    json.dumps({"message_type": 0x0E}).encode(), addr
                )
                continue

            challengeID = secrets.randbelow(0x0FFFF)
            nonce = str(secrets.randbelow(0xFFFFFFFF))
            pre_registry[challengeID] = nonce

            v_sock.sendto(
                json.dumps({
                    "message_type": 0x02,
                    "challenge_id": challengeID,
                    "nonce": nonce,
                }).encode(),
                addr,
            )

        elif msg_type == 0x03:
            cid = msg.get("challenge_id")
            stored_nonce = pre_registry.get(cid)

            if not stored_nonce:
                v_sock.sendto(
                    json.dumps({"message_type": 0x0E}).encode(), addr
                )
                continue

            expected_proof = hmac.new(
                secret, stored_nonce.encode(), hashlib.sha256
            ).hexdigest()
            if msg.get("hmac_proof") != expected_proof:
                v_sock.sendto(
                    json.dumps({"message_type": 0x0E}).encode(), addr
                )
                continue

            device_type = msg.get("device_type")
            y = secrets.randbelow(0xFFFFFFFF)
            raw_ipv6 = struct.pack(
                "!H H I I I", 0xFD00, 0xDE00, device_type, 0, y
            )
            c_ipv6 = ipaddress.IPv6Address(raw_ipv6)

            del pre_registry[cid]
            registry[str(c_ipv6)] = msg.get("pubkey")

            v_sock.sendto(
                json.dumps({
                    "message_type": 0x04,
                    "challenge_id": cid,
                    "assigned_coord": (device_type, y),
                    "assigned_ipv6": str(c_ipv6),
                    "gateway_pubkey": "indev",
                    "gateway_port": "indev",
                    "lease_seconds": 20,
                }).encode(),
                addr,
            )
            break


def client():
    time.sleep(0.2)
    c_sock = socket.socket(socket.AddressFamily.AF_INET6, socket.SOCK_DGRAM)
    c_sock.bind(("::1", 0, 0, 0))

    t_total_start = time.perf_counter()

    t_rtt1_start = time.perf_counter()
    token_hash = hashlib.sha256(secret).digest().hex()
    c_sock.sendto(
        json.dumps({
            "message_type": 0x01,
            "hash_token": token_hash,
        }).encode(),
        ("::1", VOUT_PORT, 0, 0),
    )

    data, _ = c_sock.recvfrom(2048)
    t_rtt1_end = time.perf_counter()
    msg = json.loads(data.decode("utf-8"))

    if msg.get("message_type") == 0x0E:
        print("[CLI] Error al iniciar el handshake")
        return

    t_rtt2_start = time.perf_counter()
    challenge_id = msg.get("challenge_id")
    nonce = msg.get("nonce")

    proof = hmac.new(secret, nonce.encode(), hashlib.sha256).hexdigest()

    c_sock.sendto(
        json.dumps({
            "message_type": 0x03,
            "challenge_id": challenge_id,
            "hmac_proof": proof,
            "device_type": 0x03,
            "pubkey": secrets.randbelow(0xFFFFFFFF),
        }).encode(),
        ("::1", VOUT_PORT, 0, 0),
    )

    data, _ = c_sock.recvfrom(2048)
    t_rtt2_end = time.perf_counter()
    t_total_end = time.perf_counter()

    msg = json.loads(data.decode("utf-8"))
    if msg.get("message_type") == 0x0E:
        print("[CLI] Error en autenticación")
        return

    rtt_solicit_ms = (t_rtt1_end - t_rtt1_start) * 1000
    rtt_resolve_ms = (t_rtt2_end - t_rtt2_start) * 1000
    total_ms = (t_total_end - t_total_start) * 1000

    print(f"\n[CLI] Handshake completado con éxito:")
    print(f"  * Asignación: {msg.get('assigned_ipv6')}")
    print(f"\n--- Métricas de Rendimiento DDRP ---")
    print(
        f"  1. Solicit -> Challenge: {rtt_solicit_ms:.3f} ms ({rtt_solicit_ms * 1000:.0f} µs)"
    )
    print(
        f"  2. Resolve -> Assign:    {rtt_resolve_ms:.3f} ms ({rtt_resolve_ms * 1000:.0f} µs)"
    )
    print(f"  Total Handshake:         {total_ms:.3f} ms")


if __name__ == "__main__":
    t_vout = threading.Thread(target=vanguard_out, daemon=True)
    t_cli = threading.Thread(target=client, daemon=True)

    t_vout.start()
    t_cli.start()

    t_cli.join()
    time.sleep(0.5)