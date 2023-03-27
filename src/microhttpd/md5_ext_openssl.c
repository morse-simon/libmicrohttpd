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

void
MHD_MD5 (struct Md5CtxExt *ctx,
         const unsigned char *d,
         size_t n)
{
  unsigned char *md;
  if (NULL == MD5 (d, n, md))
  {
    ctx->ext_error = 1;
  }
  else
  {
    ctx->ext_error = 0;
    memcpy (ctx->handle, md, sizeof(ctx->H));
  }
}
