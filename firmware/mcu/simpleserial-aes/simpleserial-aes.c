/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "aes-independant.h"
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_SPATIAL_HIDING
void AES128_set_config(uint8_t config);

static uint32_t lfsr = 0xACE1u;
static uint32_t prng(void) {
    uint32_t bit = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5)) & 1u;
    lfsr = (lfsr >> 1) | (bit << 15);
    return lfsr;
}

static uint8_t state_sram[16];
static uint8_t state_ccm[16] __attribute__((section(".ccmram")));
static uint8_t master_key[16];
#endif

uint8_t get_mask(uint8_t* m, uint8_t len)
{
  aes_indep_mask(m, len);
  return 0x00;
}

uint8_t get_key(uint8_t* k, uint8_t len)
{
#ifdef USE_SPATIAL_HIDING
    memcpy(master_key, k, 16);
    aes_indep_key(master_key);
#else
	aes_indep_key(k);
#endif
	return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
#ifdef USE_SPATIAL_HIDING
    // 1. Random 3-bit config (0..7)
    uint8_t config = prng() & 0x07;
    // 2. Route active pointers to SRAM or CCM
    AES128_set_config(config);
    // 3. Re-expand key into the selected buffer
    aes_indep_key(master_key);
    // 4. Select active state buffer
    uint8_t* active_state = (config & 0x04) ? state_ccm : state_sram;
    memcpy(active_state, pt, 16);

    aes_indep_enc_pretrigger(active_state);

	trigger_high();
  #ifdef ADD_JITTER
  for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
  #endif
	aes_indep_enc(active_state);
	trigger_low();

    aes_indep_enc_posttrigger(active_state);
    memcpy(pt, active_state, 16);
#else
    aes_indep_enc_pretrigger(pt);

	trigger_high();
  #ifdef ADD_JITTER
  for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);// Lancer un decalage pour chaque texte envoye'
  #endif
	aes_indep_enc(pt);
	trigger_low();

    aes_indep_enc_posttrigger(pt);
#endif
	simpleserial_put('r', 16, pt);
	return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
    // Reset key here if needed
	return 0x00;
}

static uint16_t num_encryption_rounds = 10;

uint8_t enc_multi_getpt(uint8_t* pt, uint8_t len)
{
    aes_indep_enc_pretrigger(pt);

    for(unsigned int i = 0; i < num_encryption_rounds; i++){
        trigger_high();
        aes_indep_enc(pt);
        trigger_low();
    }

    aes_indep_enc_posttrigger(pt);
	simpleserial_put('r', 16, pt);
    return 0;
}

uint8_t enc_multi_setnum(uint8_t* t, uint8_t len)
{
    //Assumes user entered a number like [0, 200] to mean "200"
    //which is most sane looking for humans I think
    num_encryption_rounds = t[1];
    num_encryption_rounds |= t[0] << 8;
    return 0;
}

#if SS_VER == SS_VER_2_1
uint8_t aes(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
{
    uint8_t req_len = 0;
    uint8_t err = 0;
    uint8_t mask_len = 0;
    if (scmd & 0x04) {
        // Mask has variable length. First byte encodes the length
        mask_len = buf[req_len];
        req_len += 1 + mask_len;
        if (req_len > len) {
            return SS_ERR_LEN;
        }
        err = get_mask(buf + req_len - mask_len, mask_len);
        if (err)
            return err;
    }

    if (scmd & 0x02) {
        req_len += 16;
        if (req_len > len) {
            return SS_ERR_LEN;
        }
        err = get_key(buf + req_len - 16, 16);
        if (err)
            return err;
    }
    if (scmd & 0x01) {
        req_len += 16;
        if (req_len > len) {
            return SS_ERR_LEN;
        }
        err = get_pt(buf + req_len - 16, 16);
        if (err)
            return err;
    }

    if (len != req_len) {
        return SS_ERR_LEN;
    }

    return 0x00;

}
#endif

int main(void)
{
#if defined(USE_CCM) || defined(USE_CCM_KEY)
	/* Key stored in CCM RAM (0x10000000) */
	static uint8_t tmp[KEY_LENGTH] __attribute__((section(".ccmram"))) = {DEFAULT_KEY};
#else
	/* Key stored in regular SRAM (0x20000000) */
	uint8_t tmp[KEY_LENGTH] = {DEFAULT_KEY};
#endif

    platform_init();
    init_uart();
    trigger_setup();

	aes_indep_init();
#ifdef USE_SPATIAL_HIDING
    memcpy(master_key, tmp, 16);
    aes_indep_key(master_key);
#else
	aes_indep_key(tmp);
#endif

    /* Uncomment this to get a HELLO message for debug */

    // putch('h');
    // putch('e');
    // putch('l');
    // putch('l');
    // putch('o');
    // putch('\n');

	simpleserial_init();
    #if SS_VER == SS_VER_2_1
    simpleserial_addcmd(0x01, 16, aes);
    #else
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('p', 16,  get_pt);
    simpleserial_addcmd('x',  0,   reset);
    simpleserial_addcmd_flags('m', 18, get_mask, CMD_FLAG_LEN);
    simpleserial_addcmd('s', 2, enc_multi_setnum);
    simpleserial_addcmd('f', 16, enc_multi_getpt);
    #endif
    while(1)
	simpleserial_get();
}
