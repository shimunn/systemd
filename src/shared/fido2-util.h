/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int fido2_generate_salt(struct iovec *ret_salt);
int fido2_read_salt_file(const char *filename, uint64_t offset, const char *client, const char *node, struct iovec *ret_salt);
int fido2_prompt_salt(const char *node, usec_t until, AskPasswordFlags flags, struct iovec *ret_salt);
int fido2_ask_salt_passphrase(const char *node, usec_t until, AskPasswordFlags flags, char **ret_passphrase);
int fido2_mix_passphrase(const void *hmac, size_t hmac_size, const char *passphrase, void **ret_key, size_t *ret_key_size);
