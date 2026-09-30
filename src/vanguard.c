#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DDRP_PORT 1025
#define MAX_SESSIONS 256
#define MAX_PEERS 1024
#define CHALLENGE_TIMEOUT 10
#define LEASE_DEFAULT 20

enum {
  DDRP_PKT_SOLICIT = 0x01,
  DDRP_PKT_CHALLENGE = 0x02,
  DDRP_PKT_RESOLVE = 0x03,
  DDRP_PKT_ASSIGN = 0x04,
  DDRP_PKT_REJECT = 0x0E
};

#pragma pack(push, 1)

typedef struct {
  uint8_t pkt_type;
  uint8_t device_type;
  uint8_t flags;
  uint16_t preferred_port;
  uint8_t client_pubkey[32];
  uint8_t token_hash[32];
  char hostname[32];
} ddrp_solicit_t;

typedef struct {
  uint8_t pkt_type;
  uint8_t nonce[32];
  uint32_t challenge_id;
} ddrp_challenge_t;

typedef struct {
  uint8_t pkt_type;
  uint32_t challenge_id;
  uint8_t hmac_proof[32];
  uint8_t device_type;
  uint8_t client_pubkey[32];
} ddrp_resolve_t;

typedef struct {
  uint8_t pkt_type;
  uint32_t challenge_id;
  uint32_t coord_x;
  uint32_t coord_y;
  uint8_t assigned_ipv6[16];
  uint8_t gateway_pubkey[32];
  uint16_t gateway_port;
  uint32_t lease_seconds;
} ddrp_assign_t;

typedef struct {
  uint8_t pkt_type;
  uint32_t challenge_id;
  uint8_t error_code;
} ddrp_reject_t;

#pragma pack(pop)

typedef struct {
  uint32_t challenge_id;
  uint8_t nonce[32];
  time_t created_at;
  int active;
} session_t;

typedef struct {
  uint32_t coord_x;
  uint32_t coord_y;
  uint8_t client_pubkey[32];
  time_t lease_expires;
  int active;
} peer_entry_t;

static session_t sessions[MAX_SESSIONS];
static peer_entry_t peers_table[MAX_PEERS];

static uint8_t master_token[32];
static uint8_t expected_token_hash[32];
static uint8_t vanguard_wg_pk[32];
static uint8_t vanguard_wg_sk[32];

// I FUCKING LOVE BEING A COMPLETE FUCKING ASSHOLE🫏🫏🫏
const char *get_wg_interface(uint32_t coord_x) {
  switch (coord_x) {
  case 0:
    return "wg0";
  case 1:
    return "wg1";
  case 2:
    return "wg2";
  case 3:
    return "wg3";
  case 4:
    return "wg4";
  default:
    return "wg5";
  }
}

void load_or_generate_master_token() {
  FILE *f = fopen("vanguard_master.key", "rb");
  if (f) {
    fread(master_token, 1, 32, f);
    fclose(f);
    printf("[VANGUARD] Master Token cargado desde archivo.\n");
  } else {
    randombytes_buf(master_token, 32);
    f = fopen("vanguard_master.key", "wb");
    if (f) {
      fwrite(master_token, 1, 32, f);
      fclose(f);
      printf("[VANGUARD] Nuevo Master Token generado y guardado en "
             "vanguard_master.key.\n");
    }
  }
  crypto_hash_sha256(expected_token_hash, master_token, 32);

  printf("[VANGUARD] Master Token (hex): ");
  for (int i = 0; i < 32; i++)
    printf("%02x", master_token[i]);
  printf("\n");
}

void load_or_generate_wg_keys(void) {
  char b64_sk[64];
  FILE *f = fopen("vanguard_wg.key", "r");

  if (f) {
    if (fgets(b64_sk, sizeof(b64_sk), f)) {
      b64_sk[strcspn(b64_sk, "\r\n")] = 0;
      size_t bin_len;
      sodium_base642bin(vanguard_wg_sk, sizeof(vanguard_wg_sk), b64_sk,
                        strlen(b64_sk), NULL, &bin_len, NULL,
                        sodium_base64_VARIANT_ORIGINAL);
    }
    fclose(f);
    crypto_scalarmult_base(vanguard_wg_pk, vanguard_wg_sk);
    printf("[VANGUARD] Clave WireGuard cargada desde vanguard_wg.key.\n");
  } else {
    randombytes_buf(vanguard_wg_sk, 32);
    vanguard_wg_sk[0] &= 248;
    vanguard_wg_sk[31] = (vanguard_wg_sk[31] & 127) | 64;

    crypto_scalarmult_base(vanguard_wg_pk, vanguard_wg_sk);

    sodium_bin2base64(b64_sk, sizeof(b64_sk), vanguard_wg_sk, 32,
                      sodium_base64_VARIANT_ORIGINAL);

    f = fopen("vanguard_wg.key", "w");
    if (f) {
      fprintf(f, "%s\n", b64_sk);
      fclose(f);
      printf("[VANGUARD] Nueva clave WireGuard guardada en Base64.\n");
    }
  }

  char b64_pk[64];
  sodium_bin2base64(b64_pk, sizeof(b64_pk), vanguard_wg_pk, 32,
                    sodium_base64_VARIANT_ORIGINAL);
  printf("[VANGUARD] WG Public Key (Base64): %s\n", b64_pk);
}

void init_keys() {
  load_or_generate_master_token();
  load_or_generate_wg_keys();
}

void setup_wg_interface(const char *iface, uint16_t port) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd),
           "wg set %s listen-port %u private-key vanguard_wg.key", iface, port);
  system(cmd);
}

void build_ipv6(uint32_t x, uint32_t y, uint8_t ipv6_out[16]) {
  ipv6_out[0] = 0xfd;
  ipv6_out[1] = 0x00;
  ipv6_out[2] = 0xde;
  ipv6_out[3] = 0x00;

  ipv6_out[4] = (x >> 24) & 0xFF;
  ipv6_out[5] = (x >> 16) & 0xFF;
  ipv6_out[6] = (x >> 8) & 0xFF;
  ipv6_out[7] = (x) & 0xFF;

  ipv6_out[8] = 0;
  ipv6_out[9] = 0;
  ipv6_out[10] = 0;
  ipv6_out[11] = 0;

  ipv6_out[12] = (y >> 24) & 0xFF;
  ipv6_out[13] = (y >> 16) & 0xFF;
  ipv6_out[14] = (y >> 8) & 0xFF;
  ipv6_out[15] = (y) & 0xFF;
}

uint32_t allocate_unique_y(uint32_t target_x) {
  uint32_t candidate_y;
  int collision;
  time_t now = time(NULL);

  while (1) {
    candidate_y = randombytes_random();
    if (candidate_y == 0)
      continue;

    collision = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
      if (peers_table[i].active && peers_table[i].coord_x == target_x) {
        if (peers_table[i].coord_y == candidate_y) {
          if (now > peers_table[i].lease_expires) {
            peers_table[i].active = 0;
            break;
          }
          collision = 1;
          break;
        }
      }
    }
    if (!collision)
      return candidate_y;
  }
}

void inject_wireguard_peer(uint32_t coord_x, const uint8_t raw_pk[32],
                           const uint8_t raw_ipv6[16]) {
  char b64_pk[64];
  sodium_bin2base64(b64_pk, sizeof(b64_pk), raw_pk, 32,
                    sodium_base64_VARIANT_ORIGINAL);

  char ip_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, raw_ipv6, ip_str, sizeof(ip_str));

  const char *iface = get_wg_interface(coord_x);

  char cmd[256];
  snprintf(cmd, sizeof(cmd), "wg set %s peer %s allowed-ips %s/128", iface,
           b64_pk, ip_str);

  printf("[WG INJECT] Ejecutando: %s\n", cmd);
  int ret = system(cmd);
  if (ret != 0) {
    fprintf(stderr, "[WARN] No se pudo ejecutar wg set (¿Permisos root o "
                    "interfaz no creada?)\n");
  }
}

void remove_wireguard_peer(uint32_t coord_x, const uint8_t raw_pk[32]) {
  char b64_pk[64];

  sodium_bin2base64(b64_pk, sizeof(b64_pk), raw_pk, 32,
                    sodium_base64_VARIANT_ORIGINAL);

  const char *iface = get_wg_interface(coord_x);
  char cmd[256];

  snprintf(cmd, sizeof(cmd), "wg set %s peer %s remove", iface, b64_pk);
  printf("[WG CLEANUP] Lease expirado. Expulsando peer: %s de %s\n", b64_pk,
         iface);
  system(cmd);
}

void sweep_expired_entries(void) {
  time_t now = time(NULL);

  for (int i = 0; i < MAX_PEERS; i++) {
    if (peers_table[i].active && now > peers_table[i].lease_expires) {
      remove_wireguard_peer(peers_table[i].coord_x,
                            peers_table[i].client_pubkey);
      peers_table[i].active = 0;
    }
  }

  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (sessions[i].active &&
        (now - sessions[i].created_at > CHALLENGE_TIMEOUT)) {
      sessions[i].active = 0;
    }
  }
}

int main(void) {
  if (sodium_init() < 0)
    return 1;
  init_keys();

  for (uint32_t x = 0; x <= 5; x++) {
    const char *iface = get_wg_interface(x);
    uint16_t port = 51820 + (uint16_t)x;
    setup_wg_interface(iface, port);
  }

  int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_in6 saddr;
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin6_family = AF_INET6;
  saddr.sin6_addr = in6addr_any;
  saddr.sin6_port = htons(DDRP_PORT);

  if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
    perror("bind");
    return 1;
  }

  printf("[VANGUARD] Centinela DDRP escuchando en puerto %d UDP...\n",
         DDRP_PORT);

  uint8_t buffer[2048];

  time_t last_sweep = 0;

  while (1) {
    time_t now = time(NULL);
    if (now - last_sweep >= 1) {
      sweep_expired_entries();
      last_sweep = now;
    }

    struct sockaddr_in6 caddr;
    socklen_t clen = sizeof(caddr);

    ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&caddr, &clen);

    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      continue;
    }
    if (n == 0)
      continue;

    uint8_t pkt_type = buffer[0];

    if (pkt_type == DDRP_PKT_SOLICIT && n >= (ssize_t)sizeof(ddrp_solicit_t)) {
      ddrp_solicit_t *req = (ddrp_solicit_t *)buffer;

      if (sodium_memcmp(req->token_hash, expected_token_hash, 32) != 0) {
        ddrp_reject_t rej = {DDRP_PKT_REJECT, 0, 0x01};
        sendto(sockfd, &rej, sizeof(rej), 0, (struct sockaddr *)&caddr, clen);
        continue;
      }

      uint32_t cid = randombytes_random() % 0x0FFFF;
      int slot = -1;
      for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active ||
            (time(NULL) - sessions[i].created_at > CHALLENGE_TIMEOUT)) {
          slot = i;
          break;
        }
      }

      if (slot == -1) {
        ddrp_reject_t rej = {DDRP_PKT_REJECT, 0, 0x04};
        sendto(sockfd, &rej, sizeof(rej), 0, (struct sockaddr *)&caddr, clen);
        continue;
      }

      sessions[slot].challenge_id = cid;
      sessions[slot].created_at = time(NULL);
      sessions[slot].active = 1;
      randombytes_buf(sessions[slot].nonce, 32);

      ddrp_challenge_t ch = {.pkt_type = DDRP_PKT_CHALLENGE,
                             .challenge_id = htonl(cid)};
      memcpy(ch.nonce, sessions[slot].nonce, 32);

      sendto(sockfd, &ch, sizeof(ch), 0, (struct sockaddr *)&caddr, clen);
    } else if (pkt_type == DDRP_PKT_RESOLVE &&
               n >= (ssize_t)sizeof(ddrp_resolve_t)) {
      ddrp_resolve_t *res = (ddrp_resolve_t *)buffer;
      uint32_t cid = ntohl(res->challenge_id);

      int slot = -1;
      for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active && sessions[i].challenge_id == cid) {
          slot = i;
          break;
        }
      }

      if (slot == -1) {
        ddrp_reject_t rej = {DDRP_PKT_REJECT, htonl(cid), 0x01};
        sendto(sockfd, &rej, sizeof(rej), 0, (struct sockaddr *)&caddr, clen);
        continue;
      }

      uint8_t expected_proof[crypto_auth_hmacsha256_BYTES];
      crypto_auth_hmacsha256(expected_proof, sessions[slot].nonce, 32,
                             master_token);

      if (sodium_memcmp(res->hmac_proof, expected_proof, 32) != 0) {
        sessions[slot].active = 0;
        ddrp_reject_t rej = {DDRP_PKT_REJECT, htonl(cid), 0x02};
        sendto(sockfd, &rej, sizeof(rej), 0, (struct sockaddr *)&caddr, clen);
        continue;
      }

      sessions[slot].active = 0;
      uint32_t coord_x = res->device_type;
      uint32_t coord_y = allocate_unique_y(coord_x);

      for (int i = 0; i < MAX_PEERS; i++) {
        if (!peers_table[i].active ||
            time(NULL) > peers_table[i].lease_expires) {
          peers_table[i].coord_x = coord_x;
          peers_table[i].coord_y = coord_y;
          memcpy(peers_table[i].client_pubkey, res->client_pubkey, 32);
          peers_table[i].lease_expires = time(NULL) + LEASE_DEFAULT;
          peers_table[i].active = 1;
          break;
        }
      }

      ddrp_assign_t assign = {.pkt_type = DDRP_PKT_ASSIGN,
                              .challenge_id = htonl(cid),
                              .coord_x = htonl(coord_x),
                              .coord_y = htonl(coord_y),
                              .gateway_port = htons(51820 + (uint16_t)coord_x),
                              .lease_seconds = htonl(LEASE_DEFAULT)};
      build_ipv6(coord_x, coord_y, assign.assigned_ipv6);
      memcpy(assign.gateway_pubkey, vanguard_wg_pk, 32);

      sendto(sockfd, &assign, sizeof(assign), 0, (struct sockaddr *)&caddr,
             clen);

      inject_wireguard_peer(coord_x, res->client_pubkey, assign.assigned_ipv6);
    }
  }

  close(sockfd);
  return 0;
}