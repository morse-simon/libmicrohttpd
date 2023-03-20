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
 * @brief  Wrapper for MD5 calculation performed by TLS library
 * @author Karlson2k (Evgeny Grin)
 * @author Edouard LEFIZELIER
 */

#include <openssl/crypto.h>
#include "md5_ext.h"
#include "mhd_assert.h"

/**
 * Initialise structure for MD5 calculation.
 *
 * @param ctx the calculation context
 */
void
MHD_MD5_init (struct Md5Ctx *ctx)
{
  MD5_CTX c;
  /*Initial Hash value, see OpenSSL manual*/
  if (1 = MD5_INIT (&c))
  {
    ctx->H[0] = c->A;
    ctx->H[1] = c->B;
    ctx->H[2] = c->C;
    ctx->H[3] = c->D;
    /* Initialise the number of bytes. */
    ctx->count = 0;
  }
  OPENSSL_cleanse (c, sizeof(*c));
}


/* à terminer */
/**
 * Process portion of bytes.
 *
 * @param ctx the calculation context
 * @param data bytes to add to hash
 * @param length number of bytes in @a data
 */
void
MHD_MD5_update (struct Md5CtxExt *ctx,
                const uint8_t *data,
                size_t length)
{
  MD5_CTX c;
  if (0 == ctx->ext_error)
    /* MD5_Update() return 1 for success, 0 otherwise.*/
    ctx->ext_error = ! MD5_Update (c, data, length);

}


/* à terminer */
/**
 * Finalise MD5 calculation, return digest, reset hash calculation.
 *
 * @param ctx the calculation context
 * @param[out] digest set to the hash, must be #MD5_DIGEST_SIZE bytes
 */
void
MHD_MD5_finish_reset (struct Md5CtxExt *ctx,
                      uint8_t digest[MD5_DIGEST_SIZE])
{
  if (0 == ctx->ext_error)
    gnutls_hash_output (ctx->handle, digest);
}


/*
typedef struct MD5state_st
  101     {
  102     MD5_LONG A,B,C,D;
  103     MD5_LONG Nl,Nh;
  104     MD5_LONG data[MD5_LBLOCK];
  105     unsigned int num;
  106     } MD5_CTX;
*/