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
#include "connection.h"
#include  "openssl/bio.h"
#include  "openssl/ssl.h"
#include  "openssl/err.h"


#if ENABLE_TLS_PLUGINS
#define PRIVATE_SYMBOL static
#else
#define PRIVATE_SYMBOL /* public */
#endif


PRIVATE_SYMBOL
enum MHD_TlsProtocolVersion
MHD_TLS_openssl_get_version (struct MHD_Connection *connection)
{
  // ...
}


struct TLS_Plugin *
MHD_TLS_openssl_init (void *ctx)
{
#define OPENSSL_API(rval,fname,fargs) \
  fname = MHD_TLS_openssl_ ## fname

  static struct TLS_Plugin plugin = {
    TLS_API (OPENSSL_API)
  };
#undef OPENSSL_API
  return &plugin;
}


FILE *err_file;

/**
 * Callback for receiving data from the socket.
 *
 * @param connection the MHD_Connection structure
 * @param other where to write received data to
 * @param i maximum size of other (in bytes)
 * @return positive value for number of bytes actually received or
 *         negative value for error number MHD_ERR_xxx_
 */
static ssize_t
recv_tls_adapter_openssl_ (struct MHD_Connection *connection,
                           void *other,
                           size_t i)
{
  ssize_t res;

  if (i > SSIZE_MAX)
    i = SSIZE_MAX;

  res = SSL_read (connection->tls.openssl.ssl,
                  other,
                  i);
  // TODO error handling
  return res
}


/**
 * Initialize the OpenSSL library
*/
void
init_openssl ()
{
  #if OPENSSL_API_LEVEL < 3000
  // deprecated since OpenSSL 3.0
  ERR_load_BIO_strings ();
  #endif
  SSL_load_error_strings ();
  OpenSSL_add_all_algorithms ();
}


/**
 * create a new SSL_CTX structure
 *
 * @return the SSL_CTX structure
*/
void
create_context (struct MHD_Connection *connection)
{
  SSL_CTX *ctx;
  ctx = SSL_CTX_new (SSLv23_client_method ());
  if (! ctx)
  {
    ERR_print_errors_fp (err_file);
  }
  connection->tls.openssl.ctx = ctx;
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
    ERR_print_errors_fp (err_file);
  }
}


/**
 * Initiat a handshake using openssl
 *
 * @param connection connection to handshake on
 * @return false if an error occured, true otherwise
*/
bool
MHD_run_tls_handshake_openssl_ (struct MHD_Connection *connection)
{
  BIO *bio = connection->tls.openssl.bio;
  bio = BIO_new_ssl_connect (connection->tls.openssl.ctx);
  SSL *ssl;
  int ret;
  unsigned long err;
  BIO_get_ssl (bio, &ssl);
  connection->tls.openssl.ssl = ssl;

  // Prevent some failure when not receiving non-application data
  SSL_set_mode (connection->tls.openssl.ssl, SSL_MODE_AUTO_RETRY);
  BIO_set_conn_hostname (bio, "localhost:8080");
  // Set the BIO in a non blocking mode
  BIO_set_nbio (bio, 1);
  if ((1 == SSL_is_init_finished (connection->tls.openssl.ssl)) ||
      (1 == SSL_in_init (connection->tls.openssl.ssl)))
  {
    ret = BIO_do_handshake (bio);
    if (1 == ret)
    {
      connection->tls.openssl.tls_state = MHD_TLS_CONN_CONNECTED;
      MHD_update_last_activity_ (connection);
      return true;
    }
    // In this block, we handle the case where the connection encountered an error
    if (0 >= ret)
    {
      // TODO
      err = ERR_get_error ();
      ERR_print_errors_fp (err_file);
      return false;
    }
  #ifdef HAVE_MESSAGES
    MHD_DLOG (connection->daemon,
              _ ("Error: received handshake message out of context.\n"));
  #endif
    MHD_connection_close_ (connection,
                           MHD_REQUEST_TERMINATED_WITH_ERROR);
    return false;
  }
  // Verify the certificate
  if (SSL_get_verify_result (connection->tls.openssl.ssl) != X509_V_OK)
  {
    ERR_print_errors_fp (err_file);
    close_connection (connection);
    return false;
  }
  return true;
}


/**
 * Set connection callback function to be used through out
 * the processing of this secure connection.
 *
 * @param connection which callbacks should be modified
 */
void
MHD_set_https_callbacks_openssl_ (struct MHD_Connection *connection)
{
  connection->recv_cls = &recv_tls_adapter_openssl_;
}


/**
 * Close the connection with the server
 *
 * @param connection to use
 * @return flase if an error occured, true otherwise
*/
bool
MHD_tls_connection_shutdown_openssl_ (struct MHD_Connection *connection)
{
  if (MHD_TLS_CONN_WR_CLOSED > connection->tls.openssl.tls_state)
  {
    // The BIO can not be reused
    const int res = BIO_free (connection->tls.openssl.bio);
    if (1 == res)
    {
      connection->tls.openssl.tls_state = MHD_TLS_CONN_WR_CLOSED;
      return true;
    }
    // In this block, we handle the case where the connection closing encountered an error
    if (0 == res)
    {
      // TODO
    }
  }
  return false;
}


/**
 * Free memory allocated by OpenSSL when the application is shutting down
 *
 * @param ctx the SSL_CTX structure
*/
void
shutting_down (struct MHD_Connection *connection)
{
  SSL_CTX_free (connection->tls.openssl.ctx);
  // Free the error strings for libcrypto and libssl
  ERR_free_strings ();
  // Cleanup all the ciphers and digests
  EVP_cleanup ();
}
