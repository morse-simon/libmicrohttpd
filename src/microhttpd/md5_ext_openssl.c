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
#include "md5_ext_openssl.h"
#include "mhd_assert.h"

void
MHD_MD5_init (struct Md5CtxExt *ctx)
{
  MD5_init (*ctx);
}


void
MHD_MD5_update (struct Md5CtxExt *ctx, const void *buf, int len)
{
  MD5_update (*ctx, *buf, len);
}


void
MHD_MD5_final (struct Md5CtxExt *ctx, unsigned char *md)
{
  MD5_final (md, *ctx);
}
