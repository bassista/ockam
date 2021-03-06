/**
********************************************************************************************************
* @file        test_default.c
* @brief
********************************************************************************************************
*/

/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmocka.h"
#include "default.h"
#include "ockam/error.h"
#include "ockam/memory.h"
#include "ockam/vault.h"
#include "test_vault.h"

/*
 ********************************************************************************************************
 *                                                DEFINES                                               *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                               CONSTANTS                                              *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                               DATA TYPES                                             *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                          FUNCTION PROTOTYPES                                         *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                            GLOBAL VARIABLES                                          *
 ********************************************************************************************************
 */

OckamVaultDefaultConfig default_cfg = {.features = OCKAM_VAULT_ALL, .ec = kOckamVaultEcCurve25519};

const OckamVault *vault = &ockam_vault_default;
const OckamMemory *memory = &ockam_memory_stdlib;

/*
 ********************************************************************************************************
 *                                           GLOBAL FUNCTIONS                                           *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                            LOCAL FUNCTIONS                                           *
 ********************************************************************************************************
 */

/**
 ********************************************************************************************************
 *                                             main()
 *
 * @brief   Main point of entry for mbedcrypto test
 *
 ********************************************************************************************************
 */

int main(void) {
  OckamError err;
  uint8_t i;
  void *default_0 = 0;

  memory->Create(0);

  cmocka_set_message_output(CM_OUTPUT_XML);

  /* ---------- */
  /* Vault Init */
  /* ---------- */

  vault->Create(&default_0, &default_cfg, memory);
  if (err != kOckamErrorNone) { /* Ensure it initialized before proceeding, otherwise */
    return -1;                  /* don't bother trying to run any other tests         */
  }

  /* ------------------------ */
  /* Random Number Generation */
  /* ------------------------ */

  TestVaultRunRandom(vault, default_0, memory);

  /* --------------------- */
  /* Key Generation & ECDH */
  /* --------------------- */

  TestVaultRunKeyEcdh(vault, default_0, memory, default_cfg.ec, 1);

  /* ------ */
  /* SHA256 */
  /* ------ */

  TestVaultRunSha256(vault, default_0, memory);

  /* -----*/
  /* HKDF */
  /* -----*/

  TestVaultRunHkdf(vault, default_0, memory);

  /* -------------------- */
  /* AES GCM Calculations */
  /* -------------------- */

  TestVaultRunAesGcm(vault, default_0, memory);

  return 0;
}
