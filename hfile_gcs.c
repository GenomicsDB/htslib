/*  hfile_gcs.c -- Google Cloud Storage backend for low-level file streams.

    Copyright (C) 2016 Genome Research Ltd.

    Author: John Marshall <jm18@sanger.ac.uk>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.  */

#define HTS_BUILDING_LIBRARY // Enables HTSLIB_EXPORT, see htslib/hts_defs.h
#include <config.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>

#include "htslib/hts.h"
#include "htslib/kstring.h"
#include "hfile_internal.h"
#ifdef ENABLE_PLUGINS
#include "version.h"
#endif

// Use mutex to allow only one thread to get/set gcs_access_token
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static time_t last_access = 0;

static void construct_auth_hdr(const char *access_token, kstring_t *auth_hdr) {
    if (access_token && strlen(access_token) > 0) {
        kputs("Authorization: Bearer ", auth_hdr);
        kputs(access_token, auth_hdr);
    }
}

static void
construct_auth_hdr_with_access_token(kstring_t *auth_hdr)
{
    // TODO Find the access token in a more standard way
    char *token = getenv("GCS_OAUTH_TOKEN");
    if (token) {
        construct_auth_hdr(token, auth_hdr);
        return;
    }

    // Allow hfile_libcurl to handle this
    if (getenv("HTS_AUTH_LOCATION")) {
        return;
    }

    // Try the service account route with the GOOGLE_APPLICATION_CREDENTIALS env.
    // See max token sizes outlined in https://developers.google.com/identity/protocols/oauth2.
    // There is no support for refresh tokens in service accounts. See token expiration explained in
    // https://developers.google.com/identity/protocols/oauth2/service-account. Access tokens are
    // set to expire in 3600 seconds. Take off 60 seconds to allow for clock skew and slow servers as
    // used in hfile_libcurl.c for AUTH_REFRESH_EARLY_SECS.
#define MAX_GCS_TOKEN_SIZE 2048
#define MAX_SERVICE_TOKEN_DURATION 3540

    static char gcs_access_token[MAX_GCS_TOKEN_SIZE];
    if (getenv("GOOGLE_APPLICATION_CREDENTIALS")) {
        pthread_mutex_lock(&lock);
        if (!last_access || (last_access &&  difftime(time(NULL), last_access)  > MAX_SERVICE_TOKEN_DURATION)) {
            memset(&gcs_access_token[0], 0, sizeof gcs_access_token);
            FILE *fp = popen("gcloud auth application-default print-access-token", "r");
            if (fp) {
                kstring_t text = { 0, 0, NULL };
                if (!kgetline(&text, (kgets_func *) fgets, fp)) {
                    pclose(fp);
                    assert(text.l <= MAX_GCS_TOKEN_SIZE);
                    strncpy(gcs_access_token, text.s, MAX_GCS_TOKEN_SIZE);
                    free(text.s);
                }
                last_access = time(NULL);
            }
        }
        construct_auth_hdr(gcs_access_token, auth_hdr);
        pthread_mutex_unlock(&lock);
    }
}

static hFILE *
gcs_rewrite(const char *gsurl, const char *mode, int mode_has_colon,
            va_list *argsp)
{
    const char *bucket, *path;
    kstring_t mode_colon = { 0, 0, NULL };
    kstring_t url = { 0, 0, NULL };
    kstring_t auth_hdr = { 0, 0, NULL };
    hFILE *fp = NULL;

    // GCS URL format is gs[+SCHEME]://BUCKET/PATH

    if (gsurl[2] == '+') {
        bucket = strchr(gsurl, ':') + 1;
        kputsn(&gsurl[3], bucket - &gsurl[3], &url);
    }
    else {
        kputs("https:", &url);
        bucket = &gsurl[3];
    }
    while (*bucket == '/') kputc(*bucket++, &url);

    path = bucket + strcspn(bucket, "/?#");

    kputsn(bucket, path - bucket, &url);
    if (strchr(mode, 'r')) kputs(".storage-download", &url);
    else if (strchr(mode, 'w')) kputs(".storage-upload", &url);
    else kputs(".storage", &url);
    kputs(".googleapis.com", &url);

    kputs(path, &url);

    if (hts_verbose >= 8)
        fprintf(stderr, "[M::gcs_open] rewrote URL as %s\n", url.s);

    construct_auth_hdr_with_access_token(&auth_hdr);

    if (argsp || auth_hdr.l > 0 || mode_has_colon) {
        if (! mode_has_colon) {
            kputs(mode, &mode_colon);
            kputc(':', &mode_colon);
            mode = mode_colon.s;
        }

        fp = hopen(url.s, mode, "va_list", argsp,
                   "httphdr", (auth_hdr.l > 0)? auth_hdr.s : NULL, NULL);
    }
    else
        fp = hopen(url.s, mode);

    free(mode_colon.s);
    free(url.s);
    free(auth_hdr.s);
    return fp;
}

static hFILE *gcs_open(const char *url, const char *mode)
{
    return gcs_rewrite(url, mode, 0, NULL);
}

static hFILE *gcs_vopen(const char *url, const char *mode_colon, va_list args0)
{
    // Need to use va_copy() as we can only take the address of an actual
    // va_list object, not that of a parameter as its type may have decayed.
    va_list args;
    va_copy(args, args0);
    hFILE *fp = gcs_rewrite(url, mode_colon, 1, &args);
    va_end(args);
    return fp;
}

int PLUGIN_GLOBAL(hfile_plugin_init,_gcs)(struct hFILE_plugin *self)
{
    static const struct hFILE_scheme_handler handler =
        { gcs_open, hfile_always_remote, "Google Cloud Storage",
          2000 + 50, gcs_vopen
        };

#ifdef ENABLE_PLUGINS
    // Embed version string for examination via strings(1) or what(1)
    static const char id[] = "@(#)hfile_gcs plugin (htslib)\t" HTS_VERSION_TEXT;
    if (hts_verbose >= 9)
        fprintf(stderr, "[M::hfile_gcs.init] version %s\n", strchr(id, '\t')+1);
#endif

    self->name = "Google Cloud Storage";
    hfile_add_scheme_handler("gs", &handler);
    hfile_add_scheme_handler("gs+http", &handler);
    hfile_add_scheme_handler("gs+https", &handler);
    return 0;
}
