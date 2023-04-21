/*
     This file is part of GNU libmicrohttpd
     Copyright (C) 2022 Evgeny Grin (Karlson2k)

     GNU libmicrohttpd is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with GNU libmicrohttpd.
     If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file microhttpd/md5_ext.h
 * @brief  Wrapper declarations for MD5 calculation performed by TLS library
 * @author Édouard LEFIZELIER
 */

#ifndef MHD_SHA1_EXT_OPENSSL
#define MHD_SHA1_EXT_OPENSSL 1

#include <openssl/crypto.h>

/**
 * SHA1 calculation context
 */
struct Sha1CtxExt_openssl
{
  SHA_CTX c; /* Hash context*/
  int ext_error; /**< Non-zero if external error occurs during init or hashing */
};

/**
 * Initialise structure for MD5 calculation
 *
 * @param ctx the calculation context
*/
void
MHD_MD5_init (struct Md5CtxExt_openssl *ctx);

/**
 * Process portion of bytes.
 *
 * @param ctx the calculation context
 * @param data bytes to add to hash
 * @param length number of bytes in @a data
*/
void
MHD_MD5_update (struct Md5CtxExt_openssl *ctx, const void *buf, int len);

/**
 * Finalise MD5 calculation, return digest.
 *
 * @param ctx the calculation context
 * @param[out] digest set to the hash, must be #MD5_DIGEST_SIZE bytes
 */
void
MHD_MD5_final (struct Md5CtxExt_openssl *ctx, unsigned char *md);


#endif
