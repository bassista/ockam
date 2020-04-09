/**
********************************************************************************************************
* @file        test_atecc608a.c
* @brief
********************************************************************************************************
*/

/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ockam/error.h"
#include "ockam/memory.h"
#include "ockam/vault.h"
#include "ockam/vault/atecc608a/atecc608a.h"
#include "ockam/vault/tests/test_vault.h"

#include "cryptoauthlib.h"
#include "atca_cfgs.h"
#include "atca_iface.h"
#include "atca_device.h"

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

ATCAIfaceCfg atca_iface_i2c = {.iface_type = ATCA_I2C_IFACE,
                               .devtype = ATECC608A,
                               {
                                   .atcai2c.slave_address = 0xC0,
                                   .atcai2c.bus = 1,
                                   .atcai2c.baud = 100000,
                               },
                               .wake_delay = 1500,
                               .rx_retries = 20};

OckamVaultAtecc608aConfig atecc608a_cfg = {.ec = kOckamVaultEcP256, .p_atca_iface_cfg = &atca_iface_i2c};

const OckamVault *vault = &ockam_vault_atecc608a;
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
  void *atecc608a_0 = 0;

  memory->Create(0); /* Always initialize memory first!                    */

  cmocka_set_message_output(CM_OUTPUT_XML); /* Configure the unit test output for JUnit XML       */

  /* ---------- */
  /* Vault Init */
  /* ---------- */

  err = vault->Create(&atecc608a_0, &atecc608a_cfg, memory);
  if (err != kOckamErrorNone) {
    return -1;
  }

  /* ------------------------ */
  /* Random Number Generation */
  /* ------------------------ */

  TestVaultRunRandom(vault, atecc608a_0, memory);

  /* --------------------- */
  /* Key Generation & ECDH */
  /* --------------------- */

  TestVaultRunKeyEcdh(vault, atecc608a_0, memory, atecc608a_cfg.ec, 0);

  /* ------ */
  /* SHA256 */
  /* ------ */

  TestVaultRunSha256(vault, atecc608a_0, memory);

  /* -----*/
  /* HKDF */
  /* -----*/

  TestVaultRunHkdf(vault, atecc608a_0, memory);

  /* -------------------- */
  /* AES GCM Calculations */
  /* -------------------- */

  TestVaultRunAesGcm(vault, atecc608a_0, memory);

  return 0;
}
