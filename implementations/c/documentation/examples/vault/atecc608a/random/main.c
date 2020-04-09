
#include "ockam/error.h"

#include "ockam/memory.h"
#include "ockam/memory/stdlib.h"

#include "ockam/vault.h"
#include "ockam/vault/atecc608a.h"

#include "ockam/io.h"
#include "ockam/io/stdio.h"


ATCAIfaceCfg atca_iface_i2c =
{
  .iface_type = ATCA_I2C_IFACE,
  .devtype = ATECC608A,
  {
    .atcai2c.slave_address = 0xC0,
    .atcai2c.bus = 1,
    .atcai2c.baud = 100000,
  },
  .wake_delay = 1500,
  .rx_retries = 20
};

/* This example program shows how to instantiate the default
 * software implementation of Ockam Vault interface and use
 * it to generate a random number. */
int main(void)
{
  int exit_code = 0;
  ockam_error_t error;

  /* Before we initialize a vault, we need to first initialize a memory
   * allocator, in this example we're using an allocator based on stdlib
   * malloc/free. */
  ockam_memory_t memory;
  error = ockam_memory_stdlib_initialize(&memory);
  if (error != OCKAM_ERROR_NONE) {
    goto exit;
  }

  /* Initialize the default software vault implementation. */
  ockam_vault_t vault;
  ockam_vault_atecc608a_options_t vault_options = {
    .memory = memory,
    .p_atca_iface_cfg = &atca_iface_i2c,
    .slot_static = 1,
    .slot_ephemeral = 2,
    .slot_hkdf = 9,
    .slot_aes = 15
  };
  error = ockam_vault_default_initialize(&vault, &vault_options);
  if (error != OCKAM_ERROR_NONE) {
    goto exit;
  }

  /* Generate an array of 32 random bytes, using the vault. */
  uint8_t random_bytes[32] = {0};
  error = ockam_vault_random_bytes_generate(vault, &random_bytes[0], sizeof(random_bytes));
  if (error != OCKAM_ERROR_NONE) {
    goto exit;
  }

  /* Print the generated random bytes. */
  ockam_io_print_buffer(&random_bytes[0], sizeof(random_bytes));

exit:
  if (error != OCKAM_ERROR_NONE) {
    exit_code = -1;
  }

  ockam_vault_cleanup(vault);
  ockam_memory_cleanup(memory);

  return exit_code;
}
