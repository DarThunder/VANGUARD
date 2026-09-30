#include <arpa/inet.h>
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

#define VOUT_PORT 1025

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

double get_time_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    printf("Uso: %s <IPv6_VANGUARD> <MASTER_TOKEN_HEX>\n", argv[0]);
    printf("Ejemplo: %s 2806:... da404a48d65a...\n", argv[0]);
    return 1;
  }

  if (sodium_init() < 0) {
    fprintf(stderr, "Error inicializando libsodium\n");
    return 1;
  }

  const char *vout_ip_str = argv[1];
  const char *token_hex = argv[2];

  uint8_t master_token[32];
  size_t bin_len;
  if (sodium_hex2bin(master_token, sizeof(master_token), token_hex,
                     strlen(token_hex), NULL, &bin_len, NULL) != 0 ||
      bin_len != 32) {
    fprintf(stderr,
            "Master token hex inválido (deben ser 64 caracteres hex)\n");
    return 1;
  }

  uint8_t token_hash[32];
  crypto_hash_sha256(token_hash, master_token, 32);

  uint8_t cli_wg_pk[32], cli_wg_sk[32];
  crypto_box_keypair(cli_wg_pk, cli_wg_sk);

  char b64_cli_pk[64];
  sodium_bin2base64(b64_cli_pk, sizeof(b64_cli_pk), cli_wg_pk, 32,
                    sodium_base64_VARIANT_ORIGINAL);
  printf("[TERMUX-CLI] Clave pública WG local: %s\n", b64_cli_pk);

  int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_in6 saddr;
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin6_family = AF_INET6;
  saddr.sin6_port = htons(VOUT_PORT);
  if (inet_pton(AF_INET6, vout_ip_str, &saddr.sin6_addr) <= 0) {
    fprintf(stderr, "Dirección IPv6 inválida\n");
    close(sockfd);
    return 1;
  }

  double t_start = get_time_ms();

  ddrp_solicit_t req;
  memset(&req, 0, sizeof(req));
  req.pkt_type = DDRP_PKT_SOLICIT;
  req.device_type = 0x03;
  req.flags = 0x01;
  req.preferred_port = htons(51823);
  memcpy(req.client_pubkey, cli_wg_pk, 32);
  memcpy(req.token_hash, token_hash, 32);
  strncpy(req.hostname, "termux-mobile", sizeof(req.hostname) - 1);

  sendto(sockfd, &req, sizeof(req), 0, (struct sockaddr *)&saddr,
         sizeof(saddr));

  uint8_t buffer[1024];
  socklen_t slen = sizeof(saddr);
  ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                       (struct sockaddr *)&saddr, &slen);
  if (n < 0) {
    perror("Timeout esperando CHALLENGE");
    close(sockfd);
    return 1;
  }

  if (buffer[0] == DDRP_PKT_REJECT) {
    printf(
        "[TERMUX-CLI] Rechazado por VANGUARD en el Paso 1 (Token inválido).\n");
    close(sockfd);
    return 1;
  }

  ddrp_challenge_t *ch = (ddrp_challenge_t *)buffer;
  uint32_t cid = ch->challenge_id;

  ddrp_resolve_t res;
  memset(&res, 0, sizeof(res));
  res.pkt_type = DDRP_PKT_RESOLVE;
  res.challenge_id = cid;
  res.device_type = 0x03;
  memcpy(res.client_pubkey, cli_wg_pk, 32);

  crypto_auth_hmacsha256(res.hmac_proof, ch->nonce, 32, master_token);

  sendto(sockfd, &res, sizeof(res), 0, (struct sockaddr *)&saddr,
         sizeof(saddr));

  n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr,
               &slen);
  if (n < 0) {
    perror("Timeout esperando ASSIGN");
    close(sockfd);
    return 1;
  }
  double t_end = get_time_ms();

  if (buffer[0] == DDRP_PKT_REJECT) {
    printf(
        "[TERMUX-CLI] Rechazado por VANGUARD en el Paso 3 (HMAC inválido).\n");
    close(sockfd);
    return 1;
  }

  ddrp_assign_t *assign = (ddrp_assign_t *)buffer;
  char assigned_ip_str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, assign->assigned_ipv6, assigned_ip_str,
            sizeof(assigned_ip_str));

  char b64_gw_pk[64];
  sodium_bin2base64(b64_gw_pk, sizeof(b64_gw_pk), assign->gateway_pubkey, 32,
                    sodium_base64_VARIANT_ORIGINAL);

  printf("\n[TERMUX-CLI] ¡Handshake DDRP binario C <-> C completado!\n");
  printf("  * Tiempo RTT Total: %0.3f ms\n", t_end - t_start);
  printf("  * Challenge ID:     %u\n", ntohl(assign->challenge_id));
  printf("  * Coordenadas:      X=%u, Y=%u\n", ntohl(assign->coord_x),
         ntohl(assign->coord_y));
  printf("  * IPv6 asignada:    %s\n", assigned_ip_str);
  printf("  * Gateway WG:       Puerto %u, PK: %s\n",
         ntohs(assign->gateway_port), b64_gw_pk);
  printf("  * Lease:            %u segundos\n", ntohl(assign->lease_seconds));

  close(sockfd);
  return 0;
}