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

#ifndef MHD_MD5_EXT_OPENSSL_H
#define MHD_MD5_EXT_OPENSSL_H 1


/*
MD5 calcul return
*/

struct Md5CtxExt_OpenSSL
{
  unsigned char *hash; /** Data's hash calculated */
  int ext_error; /** Non-zero if external error occurs during init or hashing */
};


/**
 * Indicates that MHD_MD5() function is present.
 */
#define MHD_MD5 1


/**
 * Calculate MD5 hash of the data.
 *
 * @param c the informations about the hash return
 * @param d the data to hash
 * @param n the length of the data
 */
void
MHD_MD5 (struct Md5CtxExt_OpenSSL *c,
         const unsigned char *d,
         size_t n)