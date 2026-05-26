/* This AES-128 comes from https://github.com/kokke/tiny-AES128-C which is released into public domain */

#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#ifndef AES_CONST_VAR
#if defined(USE_SPATIAL_HIDING)
/* Runtime hiding: AES_CONST_VAR must be empty so buffers live in RAM */
#define AES_CONST_VAR
#elif defined(USE_CCM) || defined(USE_CCM_SBOX)
#define AES_CONST_VAR __attribute__((section(".ccmram")))
#else
//#define AES_CONST_VAR static const
#define AES_CONST_VAR
#endif
#endif

#ifdef USE_SPATIAL_HIDING
void AES128_set_config(uint8_t config);
#endif

void AES128_ECB_encrypt(uint8_t* input, uint8_t* key, uint8_t *output);
void AES128_ECB_decrypt(uint8_t* input, uint8_t* key, uint8_t *output);

void AES128_ECB_indp_setkey(uint8_t* key);
void AES128_ECB_indp_crypto(uint8_t* input);



#endif //_AES_H_