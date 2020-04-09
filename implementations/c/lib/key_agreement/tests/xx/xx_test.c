
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "ockam/error.h"
#include "ockam/key_agreement.h"
#include "../../xx/xx_local.h"
#include "ockam/memory.h"
#include "ockam/syslog.h"
#include "ockam/transport.h"
#include "ockam/vault.h"
#include "xx_test.h"
//!!
#include "../../../../vault/default/default.h"


#define ACK "ACK"
#define ACK_SIZE 3
#define OK "OK"
#define OK_SIZE 2

bool scripted_xx = false;
bool run_initiator = false;
bool run_responder = false;
OckamInternetAddress ockam_ip;

void usage() {
  printf("OPTIONS\n");
  printf("  -a <xxx.xxx.xxx.xxx>\t\tIP Address\n");
  printf("  -p <portnum>\t\t\tPort\n");
  printf("  -s \t\t\tUse scripted test case\n\n");
}

OckamError parse_opts(int argc, char* argv[]) {
  int ch;
  OckamError status = kOckamErrorNone;
  while ((ch = getopt(argc, argv, "hsira:p:")) != -1) {
    switch (ch) {
      case 'h':
        usage();
        return 2;

      case 'a':
        strcpy(ockam_ip.IPAddress, &optarg[1]);
        break;

      case 'p':
        ockam_ip.port = atoi(&optarg[1]);
        if(0 == ockam_ip.port) printf("1. Port is zero\n");
        break;

      case 'i':
        run_initiator = true;
        break;

      case 'r':
        run_responder = true;
        break;

      case 's':
        scripted_xx = true;
        break;

      case '?':
        status = kBadParameter;
        usage();
        log_error(status, "invalid command-line arguments");
        return 2;

      default:
        break;
    }
  }

  return status;
}

/**
 ********************************************************************************************************
 *                                          TestInitiatorPrologue()
 ********************************************************************************************************
 *
 * Summary: This differs from the production handshake_prologue in that it
 *initiates the handshake with a known set of keys so that cipher results can be
 *verified along the way.
 *
 * @param xx [in/out] - pointer to handshake struct
 * @return [out] - kErrorNone on success
 */

//OckamError TestInitiatorPrologue(KeyEstablishmentXX *xx) {
//  OckamError status = kErrorNone;
//  uint8_t key[KEY_SIZE];
//  uint32_t keyBytes;
//
//  // 1. Pick a static 25519 keypair for this handshake and set it to s
//  string_to_hex(INITIATOR_STATIC, key, &keyBytes);
//  status = xx->vault->KeySetPrivate(xx->vault_ctx, kOckamVaultKeyStatic, key, KEY_SIZE);
//  if (kErrorNone != status) {
//    log_error(status, "failed to generate static keypair in initiator_step_1");
//    goto exit_block;
//  }
//
//  status = xx->vault->KeyGetPublic(xx->vault_ctx, kOckamVaultKeyStatic, xx->s, KEY_SIZE);
//  if (kErrorNone != status) {
//    log_error(status, "failed to generate get static public key in initiator_step_1");
//    goto exit_block;
//  }
//
//  // 2. Generate an ephemeral 25519 keypair for this handshake and set it to e
//  string_to_hex(INITIATOR_EPH, key, &keyBytes);
//  status = xx->vault->KeySetPrivate(xx->vault_ctx, kOckamVaultKeyEphemeral, key, KEY_SIZE);
//  if (kErrorNone != status) {
//    log_error(status, "failed to generate static keypair in initiator_step_1");
//    goto exit_block;
//  }
//
//  status = xx->vault->KeyGetPublic(xx->vault_ctx, kOckamVaultKeyEphemeral, xx->e, KEY_SIZE);
//  if (kErrorNone != status) {
//    log_error(status, "failed to generate get static public key in initiator_step_1");
//    goto exit_block;
//  }
//
//  // Nonce to 0, k to empty
//  xx->nonce = 0;
//  memset(xx->k, 0, sizeof(xx->k));
//
//  // Initialize h to "Noise_XX_25519_AESGCM_SHA256" and set prologue to empty
//  memset(&xx->h[0], 0, SHA256_SIZE);
//  memcpy(&xx->h[0], PROTOCOL_NAME, PROTOCOL_NAME_SIZE);
//
//  // Initialize ck
//  memset(&xx->ck[0], 0, SHA256_SIZE);
//  memcpy(&xx->ck[0], PROTOCOL_NAME, PROTOCOL_NAME_SIZE);
//
//  // h = SHA256(h || prologue), prologue is empty
//  mix_hash(xx, NULL, 0);
//
//exit_block:
//  return status;
//}

const OckamMemory *memory = &ockam_memory_stdlib;
extern OckamTransport ockamPosixTcpTransport;
OckamVaultDefaultConfig default_cfg = {.features = OCKAM_VAULT_ALL, .ec = kOckamVaultEcCurve25519};

int main(int argc, char *argv[]) {
  const OckamVault *vault = &ockam_vault_default;
  const OckamTransport *transport = &ockamPosixTcpTransport;

  int responder_status = 0;
  int initiator_status = 0;
  int fork_status = 0;
  int32_t responder_process = 0;

  OckamError status = kErrorNone;
  void *vault_ctx = NULL;

  /*-------------------------------------------------------------------------
   * Parse options
   *-----------------------------------------------------------------------*/
  status = parse_opts(argc, argv);
  if(kOckamErrorNone != status) {
    log_error(status, "Invalid command line args");
    goto exit_block;
  }
  printf("Address: %s\n", ockam_ip.IPAddress);
  printf("Port: %u\n", ockam_ip.port);
  printf("Initiator: %d\n", run_initiator);
  printf("Responder: %d\n", run_responder);

  /*-------------------------------------------------------------------------
   * Initialize the vault
   *-----------------------------------------------------------------------*/
  memory->Create(0);
  status = vault->Create(&vault_ctx, &default_cfg, memory);
  if (status != kErrorNone) {
    log_error(status, "ockam_vault_init failed");
    goto exit_block;
  }

  responder_process = fork();
  if (responder_process < 0) {
    log_error(kTestFailure, "Fork unsuccessful");
    status = -1;
    goto exit_block;
  }
  if (0 != responder_process) {
    // This is the initiator process, give the server a moment to come to life
    if(run_initiator) {
      sleep(1);
      status = XXTestInitiator(vault, vault_ctx);
      if (0 != status) {
        log_error(kTestFailure, "testTcpClient failed");
        initiator_status = -1;
      }
      // Get exit status from responder_process
      wait(&fork_status);
      responder_status = WEXITSTATUS(fork_status);
      if (0 != responder_status) {
        responder_status = -2;
      }
      status = responder_status + initiator_status;
    } // end if(run_initiator)
  } else {
    if(run_responder) {
      // This is the server process
      status = XXTestResponder(vault, vault_ctx);
      if (0 != status) {
        log_error(kTestFailure, "testTcpServer failed");
        status = -1;
      }
    }
  }

exit_block:
  printf("Test ended with status %0.4x\n", status);
  return status;
}
