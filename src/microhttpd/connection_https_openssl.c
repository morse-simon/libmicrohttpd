/*
     This file is part of libmicrohttpd
     Copyright (C) 2007, 2008, 2010 Daniel Pittman and Christian Grothoff
     Copyright (C) 2015-2021 Karlson2k (Evgeny Grin)

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
 * @file connection_https_openssl.c
 * @brief  Methods for managing SSL/TLS connections with the library OpenSSL. This file is only
 *         compiled if ENABLE_HTTPS is set.
 * @author Edouard LEFIZELIER
 */

#include "internal.h"
#include "connection_https_openssl.h"
#include  "openssl/bio.h"
#include  "openssl/ssl.h"
#include  "openssl/err.h"

/* Initializing OpenSSL */

SSL_load_error_strings ();
ERR_load_BIO_strings ();
OpenSSL_add_all_algorithms ();

/**
 * create a new SSL_CTX structure
 *
 * @return the SSL_CTX structure
*/
SSL_CTX *
create_context ()
{
  SSL_CTX *ctx;
  ctx = SSL_CTX_new (SSLv23_client_method ());
  if (! ctx)
  {
    ERR_print_errors (stderr);
  }
  return ctx;
}


/**
 * set the context of the SSL_CTX structure, especially the path to the trust store file
 *
 * @param ctx the SSL_CTX structure
 * @param path the path and the filename of the trust store file
*/
void
set_context (SSL_CTX *ctx, char *path)
{
  if (! SSL_CTX_load_verify_locations (ctx, path, NULL))
  {
    ERR_print_errors_fp (stderr);
  }
}


/**
 * Create a secure connection with the server
 *
 * @param bio the BIO structure
 * @param path the path to the certificate file
 * @return 1 if an error occured, 0 otherwise
*/
int
create_secure_connection (BIO *bio, const char *path)
{
  SSL_CTX *ctx = SSL_CTX_new (SSLv23_client_method ());
  SSL ssl;

  // Load the client certificate into the SSL_CTX structure
  if (! SSL_CTX_load_verify_locations (ctx, path, NULL))
  {
    // Error Handler
  }

  bio = BIO_new_ssl_connect (ctx);
  BIO_get_ssl (bio, &ssl);
  // if the server want a new handshake, OpenSSL will open it in the background
  SSL_set_mode (ssl, SSL_MODE_AUTO_RETRY);
}


/**
 * Open a secure connection with the server
 *
 * @param bio the BIO structure
 * @param port the port to connect to
 * @return 1 if an error occured, 0 otherwise
*/
int
open_secure_connection (BIO *bio, const char *port)
{
  BIO_set_conn_hostname (bio, port);
  if (BIO_do_connect (bio) <= 0)
  {
    return 1;
  }
  SSL ssl;
  BIO_get_ssl (bio, &ssl);
  if (SSL_get_verify_result (ssl) != X509_V_OK)
  {
    return 1;
  }
  ;
  return 0;
}


/**
 * Reset the BIO structure
 *
 * @param bio the BIO structure
 * @return 1 if an error occured, 0 otherwise
*/
int
reset_bio (BIO *bio)
{
  return ! BIO_reset (bio);
}


/**
 * Close the connection with the server
 *
 * @param bio the BIO structure
 * @return 1 if an error occured, 0 otherwise
*/
int
close_connection (BIO *bio)
{
  return ! BIO_free (bio);
}


/**
 * Free memory allocated by OpenSSL when the application is shutting down
 *
 * @param ctx the SSL_CTX structure
*/
void
shutting_down (SSL_CTX *ctx)
{
  SSL_CTX_free (ctx);
  // Free the error strings for libcrypto and libssl
  ERR_free_strings ();
  // Cleanup all the ciphers and digests
  EVP_cleanup ();
}
