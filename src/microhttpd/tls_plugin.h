/*
     This file is part of libmicrohttpd
     Copyright (C) 2023 Christian Grothoff

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
 * @file tls_plugin.h
 * @brief  TLS API that enables pluggable TLS use
 * @author Christian Grothoff
 */
#ifndef TLS_PLUGIN_H
#define TLS_PLUGIN_H


#define TLS_API(M)           \
  M (enum MHD_TlsProtocolVersion, get_version, struct MHD_Connection *); \
  M (void, set_callbacks, struct MHD_Connection *);                      \
  M (bool, connection_shutdown, struct MHD_Connection *);                \
  M (ssize_t, record_send, struct MHD_Connection *connection,            \
     const void *buf, size_t data_size);                                 \
  M (int, init_certificate, struct MHD_Daemon *);


#define TLS_CALLBACKS(rval,fname,...) \
  rval (*fname)(__VA_ARGS__)

struct TLS_Plugin
{
  TLS_API (TLS_CALLBACKS)
};


#if ENABLE_TLS_PLUGINS


/* If we are using a pluggable TLS library, use the plugin! */

#define TLS_PLUGIN_API(rval,fname,...)                \
  #define MHD_TLS_ ## fname daemon->tls_plugin->fname
TLS_API (TLS_PLUGIN_API)
#undef TLS_PLUGIN_API

#else
#if HTTPS_WITH_GNUTLS

/* If we are using GNUtls exclusively, define
   MHD_TLS_-API functions to directly use GNUtls variant */
#define TLS_GNUTLS_API(rval,fname,...)                \
  #define MHD_TLS_ ## fname MHD_TLS_gnutls_ ## fname
TLS_API (TLS_GNUTLS_API)
#undef TLS_GNUTLS_API

#elif HTTPS_WITH_OPENSSL

/* If we are using OpenSSL exclusively, define
   MHD_TLS_-API functions to directly use OpenSSL variant */
#define TLS_OPENSSL_API(rval,fname,...)                \
  #define MHD_TLS_ ## fname MHD_TLS_openssl_ ## fname
TLS_API (TLS_OPENSSL_API)
#undef TLS_OPENSSL_API

#elif HTTPS_WITH_MBEDTLS

/* If we are using Mbedtls exclusively, define
   MHD_TLS_-API functions to directly use Mbedtls variant */
#define TLS_MBEDTLS_API(rval,fname,...)                \
  #define MHD_TLS_ ## fname MHD_TLS_mbedtls_ ## fname
TLS_API (TLS_MBEDTLS_API)
#undef TLS_MBEDTLS_API

#else
#error WTF
#endif
#endif

#endif
