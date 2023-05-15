/*
     This file is part of libmicrohttpd
     Copyright (C) 2008 Daniel Pittman and Christian Grothoff

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file connection_https.h
 * @brief  Methods for managing connections
 * @author Edouard LEFIZELIER
 */

#ifndef CONNECTION_HTTPS_EXT_OPENSSL_H
#define CONNECTION_HTTPS_EXT_OPENSSL_H

#include "internal.h"
/* Not sure about those includes */
#include  "openssl/bio.h"
#include  "openssl/ssl.h"
#include  "openssl/err.h"

#ifdef HTTPS_SUPPORT
/**
 * Initialize the OpenSSL library
*/
void
init_openssl ();

/**
 * create a new SSL_CTX structure
 *
 * @return the SSL_CTX structure
*/
SSL_CTX *
create_context ();

/**
 * set the context of the SSL_CTX structure, especially the path to the trust store file
 *
 * @param ctx the SSL_CTX structure
 * @param path the path and the filename of the trust store file
*/
void
set_context (SSL_CTX *ctx, const char *path);


/**
 * Create a secure connection with the server
 *
 * @param bio the BIO structure
 * @param path the path to the certificate file
 * @return 1 if an error occured, 0 otherwise
*/
int
create_secure_connection (SSL_CTX *ctx, const char *hostnname, const char *port,
                          struct MHD_Connection *connection);


/**
 * Reset the BIO structure
 *
 * @param bio the BIO structure
 * @return 1 if an error occured, 0 otherwise
*/
int
reset_bio (BIO *bio);


/**
 * Close the connection with the server
 *
 * @param bio the BIO structure
 * @return 1 if an error occured, 0 otherwise
*/
int
close_connection (BIO *bio, struct MHD_Connection *connection);


/**
 * Free memory allocated by OpenSSL when the application is shutting down
 *
 * @param ctx the SSL_CTX structure
*/
void
shutting_down (SSL_CTX *ctx);

#endif /* HTTPS_SUPPORT */

#endif
