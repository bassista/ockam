
#include "ockam/error.h"
#include "ockam/memory.h"

#include "cryptoauthlib.h"
#include "atca_cfgs.h"
#include "atca_iface.h"
#include "atca_device.h"

typedef struct {
  ockam_memory_t memory;
  ATCAIfaceCfg *p_atca_iface_cfg;
  uint8_t slot_static;
  uint8_t slot_ephemeral;
  uint8_t slot_hkdf;
  uint8_t slot_aes;
} ockam_vault_atecc508a_options_t;


ockam_error_t ockam_vault_default_initialize(ockam_vault_t* vault, ockam_vault_default_options_t* options);

ockam_error_t ockam_vault_default_initialize(ockam_vault_t* vault, ockam_vault_default_options_t* options) {
  return 0;
}
