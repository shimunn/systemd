/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "fido2-util.h"
#include "fileio.h"
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

int fido2_prompt_salt(
                const char *node,
                usec_t until,
                AskPasswordFlags flags,
                struct iovec *ret_salt) {

        _cleanup_strv_free_erase_ char **passphrases = NULL;
        _cleanup_(iovec_done_erase) struct iovec salt = {};
        int r;

        assert(ret_salt);

        /* Asks the user for a passphrase and derives the FIDO2 salt from it by hashing it with SHA-256. The
         * passphrase is never stored anywhere, and never cached either. */

        if (FLAGS_SET(flags, ASK_PASSWORD_HEADLESS))
                return log_error_errno(
                                SYNTHETIC_ERRNO(ENOPKG),
                                "FIDO2 salt prompting requested, but the 'headless' parameter was set.");

        AskPasswordRequest req = {
                .tty_fd = -EBADF,
                .message = "Please enter FIDO2 salt passphrase:",
                .icon = "drive-harddisk",
                .id = node,
                .keyring = NULL, /* never cache the salt passphrase */
                .credential = NULL,
                .until = until,
                .hup_fd = -EBADF,
        };

        r = ask_password_auto(&req, flags & ~(ASK_PASSWORD_ACCEPT_CACHED|ASK_PASSWORD_PUSH_CACHE), &passphrases);
        if (r < 0)
                return log_error_errno(r, "Failed to ask for FIDO2 salt passphrase: %m");

        if (strv_isempty(passphrases) || isempty(passphrases[0]))
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "No FIDO2 salt passphrase provided.");

        salt.iov_base = malloc(SHA256_DIGEST_SIZE);
        if (!salt.iov_base)
                return log_oom();
        salt.iov_len = SHA256_DIGEST_SIZE;

        sha256_direct(passphrases[0], strlen(passphrases[0]), salt.iov_base);

        *ret_salt = TAKE_STRUCT(salt);
        return 0;
}
