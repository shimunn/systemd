/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "fido2-util.h"
#include "fileio.h"
#include "hmac.h"
#include "iovec-util.h"
#include "libfido2-util.h"
#include "log.h"
#include "random-util.h"
#include "sha256.h"
#include "strv.h"

int fido2_generate_salt(struct iovec *ret_salt) {
        _cleanup_(iovec_done) struct iovec salt = {};
        int r;

        assert(ret_salt);

        r = crypto_random_bytes_allocate_iovec(FIDO2_SALT_SIZE, &salt);
        if (r < 0)
                return log_error_errno(r, "Failed to generate FIDO2 salt: %m");

        *ret_salt = TAKE_STRUCT(salt);
        return 0;
}

int fido2_read_salt_file(const char *filename, uint64_t offset, const char *client, const char *node, struct iovec *ret_salt) {
        _cleanup_(iovec_done_erase) struct iovec salt = {};
        _cleanup_free_ char *bind_name = NULL;
        int r;

        assert(ret_salt);

        /* If we read the salt via AF_UNIX, make the client recognizable */
        if (asprintf(&bind_name, "@%" PRIx64"/%s-fido2-salt/%s", random_u64(), client, node) < 0)
                return log_oom();

        r = read_full_file_full(
                        AT_FDCWD, filename,
                        offset == 0 ? UINT64_MAX : offset,
                        /* size= */ FIDO2_SALT_SIZE,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|
                        READ_FULL_FILE_CONNECT_SOCKET|READ_FULL_FILE_FAIL_WHEN_LARGER,
                        bind_name, (char**) &salt.iov_base, &salt.iov_len);
        if (r == -E2BIG || (r >= 0 && salt.iov_len != FIDO2_SALT_SIZE))
                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL),
                                       "FIDO2 salt file must contain exactly %u bytes.", FIDO2_SALT_SIZE);
        if (r < 0)
                return log_error_errno(r, "Reading FIDO2 salt file '%s' failed: %m", filename);

        *ret_salt = TAKE_STRUCT(salt);
        return 0;
}

int fido2_ask_salt_passphrase(
                const char *node,
                usec_t until,
                AskPasswordFlags flags,
                char **ret_passphrase) {

        _cleanup_strv_free_erase_ char **passphrases = NULL;
        _cleanup_(erase_and_freep) char *passphrase = NULL;
        int r;

        assert(ret_passphrase);

        if (FLAGS_SET(flags, ASK_PASSWORD_HEADLESS))
                return log_error_errno(
                                SYNTHETIC_ERRNO(ENOPKG),
                                "FIDO2 passphrase prompting requested, but the 'headless' parameter was set.");

        AskPasswordRequest req = {
                .tty_fd = -EBADF,
                .message = "Please enter FIDO2 salt passphrase:",
                .icon = "drive-harddisk",
                .id = node,
                .keyring = NULL, /* never cache the passphrase */
                .credential = NULL,
                .until = until,
                .hup_fd = -EBADF,
        };

        r = ask_password_auto(&req, flags & ~(ASK_PASSWORD_ACCEPT_CACHED|ASK_PASSWORD_PUSH_CACHE), &passphrases);
        if (r < 0)
                return log_error_errno(r, "Failed to ask for FIDO2 salt passphrase: %m");

        /* TODO: when enrolling, ask twice. A typo here makes the key unrecoverable. */
        if (strv_isempty(passphrases) || isempty(passphrases[0]))
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "No FIDO2 salt passphrase provided.");

        passphrase = strdup(passphrases[0]);
        if (!passphrase)
                return log_oom();

        *ret_passphrase = TAKE_PTR(passphrase);
        return 0;
}

int fido2_prompt_salt(
                const char *node,
                usec_t until,
                AskPasswordFlags flags,
                struct iovec *ret_salt) {

        _cleanup_(erase_and_freep) char *passphrase = NULL;
        _cleanup_(iovec_done_erase) struct iovec salt = {};
        int r;

        assert(ret_salt);

        /* Mode "prompt": salt = SHA-256(passphrase). The salt is sent to the token, never stored. */

        r = fido2_ask_salt_passphrase(node, until, flags, &passphrase);
        if (r < 0)
                return r;

        salt.iov_base = malloc(SHA256_DIGEST_SIZE);
        if (!salt.iov_base)
                return log_oom();
        salt.iov_len = SHA256_DIGEST_SIZE;

        sha256_direct(passphrase, strlen(passphrase), salt.iov_base);

        *ret_salt = TAKE_STRUCT(salt);
        return 0;
}

int fido2_mix_passphrase(
                const void *hmac,
                size_t hmac_size,
                const char *passphrase,
                void **ret_key,
                size_t *ret_key_size) {

        /* Mode "mix": the token's hmac-secret output (keyed by the stored, random salt) is combined with a
         * passphrase that is never stored. The label gives domain separation and a version, so that the
         * construction can be changed later without ambiguity. The hmac-secret output is the HMAC key, so
         * the result is a PRF of the passphrase under a secret the attacker only has with the token. */

        static const char label[] = "io.systemd.cryptsetup.fido2-mix-passphrase.v1";
        _cleanup_(erase_and_freep) uint8_t *buf = NULL;
        _cleanup_(erase_and_freep) uint8_t *key = NULL;
        size_t n;

        assert(hmac);
        assert(hmac_size > 0);
        assert(passphrase);
        assert(ret_key);
        assert(ret_key_size);

        n = sizeof(label) /* includes the trailing NUL as separator */ + strlen(passphrase);
        buf = malloc(n);
        if (!buf)
                return log_oom();

        memcpy(buf, label, sizeof(label));
        memcpy(buf + sizeof(label), passphrase, strlen(passphrase));

        key = malloc(SHA256_DIGEST_SIZE);
        if (!key)
                return log_oom();

        hmac_sha256(hmac, hmac_size, buf, n, key);

        *ret_key = TAKE_PTR(key);
        *ret_key_size = SHA256_DIGEST_SIZE;
        return 0;
}
