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
set_context (SSL_CTX *ctx, const char *path)
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
create_secure_connection (SSL_CTX *ctx, const char *hostnname, const char *port,
                          struct MHD_Connection *connection)
{
  BIO *bio = BIO_new_ssl_connect (ctx);
  SSL *ssl;
  int ret;
  unsigned long err;
  BIO_get_ssl (bio, &ssl);

  // Prevent some failure when not receiving non-application data
  SSL_set_mode (ssl, SSL_MODE_AUTO_RETRY);
  BIO_set_conn_hostname (bio, hostnname);
  // Set the BIO in a non blocking mode
  BIO_set_nbio (bio, 1);
  if ((MHD_TLS_CONN_INIT == connection->tls.openssl.tls_session) ||
      (MHD_TLS_CONN_HANDSHAKING == connection->tls.openssl.tls_state))
  {
    ret = BIO_do_handshake (bio);
    if (1 == ret)
    {
      connection->tls.openssl.tls_state = MHD_TLS_CONN_CONNECTED;
      MHD_update_last_activity_ (connection);
      return 0;
    }
    // In this block, we handle the case where the connection encountered an error
    if (0 >= ret)
    {
      // TODO
      err = ERR_get_error ();
      ERR_print_errors_fp (stderr);
      return 1;
    }
  #ifdef HAVE_MESSAGES
    MHD_DLOG (connection->daemon,
              _ ("Error: received handshake message out of context.\n"));
  #endif
    MHD_connection_close_ (connection,
                           MHD_REQUEST_TERMINATED_WITH_ERROR);
    return 1;
  }
  // Verify the certificate
  if (SSL_get_verify_result (ssl) != X509_V_OK)
  {
    ERR_print_errors_fp (stderr);
    close_connection (bio, connection);
    return 1;
  }

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
close_connection (BIO *bio, struct MHD_Connection *connection)
{
  if (MHD_TLS_CONN_WR_CLOSED > connection->tls.openssl.tls_state)
  {
    // The BIO can not be reused
    const int res = BIO_free (bio);
    if (1 == res)
    {
      connection->tls.openssl.tls_state = MHD_TLS_CONN_WR_CLOSED;
      return 0;
    }
    // In this block, we handle the case where the connection closing encountered an error
    if (0 == res)
    {
      // TODO
    }
  }

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
