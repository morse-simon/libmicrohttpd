/*
     This file is part of libmicrohttpd
     Copyright (C) 2019-2021 Karlson2k (Evgeny Grin)

     libmicrohttpd is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library.
     If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file microhttpd/sha1.c
 * @brief  Calculation of SHA-1 digest as defined in FIPS PUB 180-4 (2015)
 * @author Édouard LEFIZELIER
 */

#include <openssl/crypto.h>
#include "sha1_ext_openssl.h"

/**
 * Initialise structure for SHA-1 calculation
 *
 * @param ctx the calculation context
 */
void
MHD_SHA1_init (struct Sha1CtxExt_openssl *ctx)
{
  ctx->ext_error = ! SHA1_Init (&ctx->c);
}


/**
 * Process portion of bytes.
 *
 * @param ctx the calculation context
 * @param data bytes to add to hash
 * @param length number of bytes in @a data
 */
void
MHD_SHA1_update (struct Sha1CtxExt_openssl *ctx, const void *buf, int len)
{
  if (0 == ctx->ext_error)
  {
    ctx->ext_error = ! SHA1_Update (&ctx->c, buf, len);
  }
}


/**
 * Finalise SHA-1 calculation, return digest.
 *
 * @param ctx the calculation context
 * @param md where to store the digest
 */
void
MHD_SHA1_final (struct Sha1CtxExt_openssl *ctx, void *md)
{
  if (0 == ctx->ext_error)
  {
    ctx->ext_error = ! SHA1_Final (md, &ctx->c);
  }
}
