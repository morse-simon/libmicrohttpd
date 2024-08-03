/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Christian Grothoff

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file libtest_convenience_server_reply.c
 * @brief convenience functions that generate
 *   replies from the server for libtest users
 * @author Christian Grothoff
 */
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "microhttpd2.h"
#include "libtest.h"
#include <curl/curl.h>


const struct MHD_Action *
MHDT_server_reply_text (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *text = cls;

  return MHD_action_from_response (
    request,
    MHD_response_from_buffer_static (MHD_HTTP_STATUS_OK,
                                     strlen (text),
                                     text));
}


const struct MHD_Action *
MHDT_server_reply_file (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *text = cls;
  size_t tlen = strlen (text);
  char fn[] = "/tmp/mhd-test-XXXXXX";
  int fd;

  fd = mkstemp (fn);
  if (-1 == fd)
  {
    fprintf (stderr,
             "Failed to mkstemp() temporary file\n");
    return NULL;
  }
  if (tlen != write (fd, text, tlen))
  {
    fprintf (stderr,
             "Failed to write() temporary file in one go: %s\n",
             strerror (errno));
    return NULL;
  }
  fsync (fd);
  if (0 != remove (fn))
  {
    fprintf (stderr,
             "Failed to remove() temporary file %s: %s\n",
             fn,
             strerror (errno));
  }
  return MHD_action_from_response (
    request,
    MHD_response_from_fd (MHD_HTTP_STATUS_OK,
                          fd,
                          0 /* offset */,
                          tlen));
}


const struct MHD_Action *
MHDT_server_reply_with_header (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *header = cls;
  size_t hlen = strlen (header) + 1;
  char name[hlen];
  const char *colon = strchr (header, ':');
  const char *value;
  struct MHD_Response *resp;

  memcpy (name,
          header,
          hlen);
  name[colon - header] = '\0';
  value = &name[colon - header + 1];

  resp = MHD_response_from_empty (MHD_HTTP_STATUS_NO_CONTENT);
  if (MHD_SC_OK !=
      MHD_response_add_header (resp,
                               name,
                               value))
    return NULL;
  return MHD_action_from_response (
    request,
    resp);
}


const struct MHD_Action *
MHDT_server_reply_check_query (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *equery = cls;
  size_t qlen = strlen (equery) + 1;
  char qc[qlen];

  memcpy (qc,
          equery,
          qlen);
  for (const char *tok = strtok (qc, "&");
       NULL != tok;
       tok = strtok (NULL, "&"))
  {
    const char *end;
    const struct MHD_StringNullable *sn;
    const char *val;

    end = strchr (tok, '=');
    if (NULL == end)
    {
      end = &tok[strlen (tok)];
      val = NULL;
    }
    else
    {
      val = end + 1;
    }
    {
      size_t alen = end - tok;
      char arg[alen + 1];

      memcpy (arg,
              tok,
              alen);
      arg[alen] = '\0';
      sn = MHD_request_get_value (request,
                                  MHD_VK_GET_ARGUMENT,
                                  arg);
      if (NULL == sn)
      {
        fprintf (stderr,
                 "NULL returned for query key %s\n",
                 arg);
        return NULL;
      }
      if (NULL == val)
      {
        if (NULL != sn->cstr)
        {
          fprintf (stderr,
                   "NULL expected for value for query key %s, got %s\n",
                   arg,
                   sn->cstr);
          return NULL;
        }
      }
      else
      {
        if (NULL == sn->cstr)
        {
          fprintf (stderr,
                   "%s expected for value for query key %s, got NULL\n",
                   val,
                   arg);
          return NULL;
        }
        if (0 != strcmp (val,
                         sn->cstr))
        {
          fprintf (stderr,
                   "%s expected for value for query key %s, got %s\n",
                   val,
                   arg,
                   sn->cstr);
          return NULL;
        }
      }
    }
  }

  return MHD_action_from_response (
    request,
    MHD_response_from_empty (
      MHD_HTTP_STATUS_NO_CONTENT));
}


const struct MHD_Action *
MHDT_server_reply_check_header (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *want = cls;
  size_t wlen = strlen (want) + 1;
  char key[wlen];
  const char *colon = strchr (want, ':');
  const struct MHD_StringNullable *have;
  const char *value;

  memcpy (key,
          want,
          wlen);
  if (NULL != colon)
  {
    key[colon - want] = '\0';
    value = &key[colon - want + 1];
  }
  else
  {
    value = NULL;
  }
  have = MHD_request_get_value (request,
                                MHD_VK_HEADER,
                                key);
  if (NULL == have)
  {
    fprintf (stderr,
             "Missing client header `%s'\n",
             want);
    return NULL;
  }
  if (NULL == value)
  {
    if (NULL != have->cstr)
    {
      fprintf (stderr,
               "Have unexpected client header `%s': `%s'\n",
               key,
               have->cstr);
      return NULL;
    }
  }
  else
  {
    if (NULL == have->cstr)
    {
      fprintf (stderr,
               "Missing value for client header `%s'\n",
               want);
      return NULL;
    }
    if (0 != strcmp (have->cstr,
                     value))
    {
      fprintf (stderr,
               "Client HTTP header `%s' was expected to be `%s' but is `%s'\n",
               key,
               value,
               have->cstr);
      return NULL;
    }
  }
  return MHD_action_from_response (
    request,
    MHD_response_from_empty (
      MHD_HTTP_STATUS_NO_CONTENT));
}


/**
 * Function to process data uploaded by a client.
 *
 * @param cls the payload we expect to be uploaded as a 0-terminated string
 * @param request the request is being processed
 * @param content_data_size the size of the @a content_data,
 *                          zero when all data have been processed
 * @param[in] content_data the uploaded content data,
 *                         may be modified in the callback,
 *                         valid only until return from the callback,
 *                         NULL when all data have been processed
 * @return action specifying how to proceed:
 *         #MHD_upload_action_continue() to continue upload (for incremental
 *         upload processing only),
 *         #MHD_upload_action_suspend() to stop reading the upload until
 *         the request is resumed,
 *         #MHD_upload_action_abort_request() to close the socket,
 *         or a response to discard the rest of the upload and transmit
 *         the response
 * @ingroup action
 */
static const struct MHD_UploadAction *
check_upload_cb (void *cls,
                 struct MHD_Request *request,
                 size_t content_data_size,
                 void *content_data)
{
  const char *want = cls;
  size_t wlen = strlen (want);

  if (content_data_size != wlen)
  {
    fprintf (stderr,
             "Invalid body size given to full upload callback\n");
    return NULL;
  }
  if (0 != memcmp (want,
                   content_data,
                   wlen))
  {
    fprintf (stderr,
             "Invalid body data given to full upload callback\n");
    return NULL;
  }
  /* success! */
  return MHD_upload_action_from_response (
    request,
    MHD_response_from_empty (
      MHD_HTTP_STATUS_NO_CONTENT));
}


const struct MHD_Action *
MHDT_server_reply_check_upload (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *want = cls;
  size_t wlen = strlen (want);

  return MHD_action_process_upload_full (request,
                                         wlen,
                                         &check_upload_cb,
                                         (void *) want);
}


/**
 * Closure for #chunk_return.
 */
struct ChunkContext
{
  /**
   * Where we are in the buffer.
   */
  const char *pos;
};


/**
 * Function that returns a string in chunks.
 *
 * @param dyn_cont_cls must be a `struct ChunkContext`
 * @param ctx the context to produce the action to return,
 *            the pointer is only valid until the callback returns
 * @param pos position in the datastream to access;
 *        note that if a `struct MHD_Response` object is re-used,
 *        it is possible for the same content reader to
 *        be queried multiple times for the same data;
 *        however, if a `struct MHD_Response` is not re-used,
 *        libmicrohttpd guarantees that "pos" will be
 *        the sum of all data sizes provided by this callback
 * @param[out] buf where to copy the data
 * @param max maximum number of bytes to copy to @a buf (size of @a buf)
 * @return action to use,
 *         NULL in case of any error (the response will be aborted)
 */
static const struct MHD_DynamicContentCreatorAction *
chunk_return (void *cls,
              struct MHD_DynamicContentCreatorContext *ctx,
              uint_fast64_t pos,
              void *buf,
              size_t max)
{
  struct ChunkContext *cc = cls;
  size_t imax = strlen (cc->pos);
  const char *space = strchr (cc->pos, ' ');

  if (0 == imax)
    return MHD_DCC_action_finish (ctx);
  if (NULL != space)
    imax = space - cc->pos + 1;
  if (imax > max)
    imax = max;
  memcpy (buf,
          cc->pos,
          imax);
  cc->pos += imax;
  return MHD_DCC_action_continue (ctx,
                                  imax);
}


const struct MHD_Action *
MHDT_server_reply_chunked_text (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *text = cls;
  struct ChunkContext *cc;

  cc = malloc (sizeof (struct ChunkContext));
  if (NULL == cc)
    return NULL;
  cc->pos = text;

  return MHD_action_from_response (
    request,
    MHD_response_from_callback (MHD_HTTP_STATUS_OK,
                                MHD_SIZE_UNKNOWN,
                                &chunk_return,
                                cc,
                                &free));
}


/**
 * Compare two strings, succeed if both are NULL.
 *
 * @param wants string we want
 * @param have string we have
 * @return true if what we @a want is what we @a have
 */
static bool
nstrcmp (const char *wants,
         const struct MHD_StringNullable *have)
{
  if ( (NULL == wants) &&
       (NULL == have->cstr) )
    return true;
  if ( (NULL == wants) ||
       (NULL == have->cstr) )
    return false;
  return (0 == strcmp (wants,
                       have->cstr));
}


/**
 * "Stream" reader for POST data.
 * This callback is called to incrementally process parsed POST data sent by
 * the client.
 *
 * @param cls user-specified closure
 * @param name 0-terminated key for the value
 * @param filename name of the uploaded file, NULL if not known
 * @param content_type mime-type of the data, NULL if not known
 * @param encoding the encoding of the data
 * @param data pointer to @a size bytes of data at the
 *             specified @a off offset,
 *             NOT zero-terminated
 * @param off offset of data in the overall value
 * @param size number of bytes in @a data available
 * @return action specifying how to proceed:
 *         #MHD_upload_action_continue() if all is well,
 *         #MHD_upload_action_suspend() to stop reading the upload until
 *         the request is resumed,
 *         #MHD_upload_action_abort_request() to close the socket,
 *         or a response to discard the rest of the upload and transmit
 *         the response
 * @ingroup action
 */
static const struct MHD_UploadAction *
post_stream_reader (void *cls,
                    const struct MHD_String *name,
                    const struct MHD_StringNullable *filename,
                    const struct MHD_StringNullable *content_type,
                    const struct MHD_StringNullable *encoding,
                    const void *data,
                    uint_fast64_t off,
                    size_t size)
{
  struct MHDT_PostInstructions *pi = cls;
  struct MHDT_PostWant *wants = pi->wants;

  if (NULL != wants)
  {
    for (unsigned int i = 0; NULL != wants[i].key; i++)
    {
      struct MHDT_PostWant *want = &wants[i];

      if (want->satisfied)
        continue;
      if (0 != strcmp (want->key,
                       name->cstr))
        continue;
      if (! nstrcmp (want->filename,
                     filename))
        continue;
      if (! nstrcmp (want->content_type,
                     content_type))
        continue;
      if (! want->incremental)
        continue;
      if (want->value_off != off)
        continue;
      if (want->value_size < off + size)
        continue;
      if (0 != memcmp (data,
                       want->value + off,
                       size))
        continue;
      want->value_off += size;
      want->satisfied = (want->value_size == want->value_off);
    }
  }

  return MHD_upload_action_continue (NULL);
}


/**
 * Iterator over name-value pairs.  This iterator can be used to
 * iterate over all of the cookies, headers, or POST-data fields of a
 * request, and also to iterate over the headers that have been added
 * to a response.
 *
 * The pointers to the strings in @a nvt are valid until the response
 * is queued. If the data is needed beyond this point, it should be copied.
 *
 * @param cls closure
 * @param nvt the name, the value and the kind of the element
 * @return #MHD_YES to continue iterating,
 *         #MHD_NO to abort the iteration
 * @ingroup request
 */
static enum MHD_Bool
check_complete_value (
  void *cls,
  const struct MHD_NameValueKind *nvt)
{
  struct MHDT_PostInstructions *pi = cls;
  struct MHDT_PostWant *wants = pi->wants;

  if (NULL == wants)
    return MHD_NO;
  for (unsigned int i = 0; NULL != wants[i].key; i++)
  {
    struct MHDT_PostWant *want = &wants[i];

    if (want->satisfied)
      continue;
    if (want->incremental)
      continue;
    if (0 != strcmp (want->key,
                     nvt->nv.name.cstr))
      continue;
    if (want->value_size != nvt->nv.value.len)
      continue;
    if (0 == memcmp (nvt->nv.value.cstr,
                     want->value,
                     want->value_size))
      want->satisfied = true;
  }
  return MHD_YES;
}


/**
 * The callback to be called when finished with processing
 * of the postprocessor upload data.
 * @param req the request
 * @param cls the closure
 * @return the action to proceed
 */
static const struct MHD_UploadAction *
post_stream_done (struct MHD_Request *req,
                  void *cls)
{
  struct MHDT_PostInstructions *pi = cls;

  MHD_request_get_values_cb (req,
                             MHD_VK_POSTDATA,
                             &check_complete_value,
                             pi);
  struct MHDT_PostWant *wants = pi->wants;

  if (NULL != wants)
  {
    for (unsigned int i = 0; NULL != wants[i].key; i++)
    {
      struct MHDT_PostWant *want = &wants[i];

      if (want->satisfied)
        continue;
      fprintf (stderr,
               "Expected key-value pair `%s' missing\n",
               want->key);
      return NULL;
    }
  }
  return MHD_upload_action_from_response (
    req,
    MHD_response_from_empty (
      MHD_HTTP_STATUS_NO_CONTENT));
}


const struct MHD_Action *
MHDT_server_reply_check_post (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  struct MHDT_PostInstructions *pi = cls;

  return MHD_action_parse_post (request,
                                pi->buffer_size,
                                pi->auto_stream_size,
                                pi->enc,
                                &post_stream_reader,
                                pi,
                                &post_stream_done,
                                pi);
}
