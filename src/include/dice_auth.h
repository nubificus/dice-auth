#pragma once

/* Dice authentication:
 * Check whether the DICE Attestation
 * certificate (`cert_pem`) is verified
 * against the DICE Root certificate
 * (`ca_pem`)
 * */
int dice_auth(const char *ca_pem, const char *cert_pem);
