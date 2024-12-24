/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2019 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

/*****************************************************************************
written by
   Haivision Systems Inc.

   2022-05-19 (jdube)
        OpenSSL EVP CRYSPR/4SRT (CRYypto Service PRovider for SRT).

Updated by
    Quantropi Inc.
    2024-40-06 (Dafu)
        Support Quantropi QiSpace QEEP Provider 
*****************************************************************************/

#include "hcrypt.h"

#include <string.h>

//#define DEBUG

#ifdef DEBUG
#define DBG_PRINT printf
#define HEXDUMP(s,a,b) hexdump(s, a,b)
void hexdump(char *s, const void *ptr, size_t len)
{
    const unsigned char *p = ptr;
    size_t i, j;
    if (s != NULL) printf("%s (%d): \n", s, (int)len);
    for (i = 0; i < len; i += j) {
        for (j = 0; j < 16 && i + j < len; j++)
            printf("%s%02x", j? "" : " ", p[i + j]);
    }
    printf("\n");
}
#else
#define DBG_PRINT(...)
#define HEXDUMP(s,a,b)
#endif


#ifdef _QEEP_ENABLED
#include <openssl/provider.h>
static  OSSL_PROVIDER *prov = NULL;

static unsigned char _QEEP_DEFAULT_IV[16]={0x68,0x30,0xEF,0xC1, 0xC6,0x55,0x9D,0x31, 0x5F,0xD6,0x35,0xBD, 0x7E,0x59,0xEA,0xA5 }; 

#endif

typedef struct tag_crysprOpenSSL_EVP_cb
{
    CRYSPR_cb ccb;
    /* Add cryptolib specific data here */
} crysprOpenSSL_EVP_cb;

int crysprOpenSSL_EVP_Prng(unsigned char* rn, int len)
{
    DBG_PRINT("IN-1 %s, len=%d \n", __func__, len);
    int ilen = len;
    if (ilen > 32 ) ilen = 32;
    return (RAND_bytes(rn, ilen) <= 0 ? -1 : 0);
}

const EVP_CIPHER* (*Xcipher_fnptr)(void) = EVP_aes_128_ecb;

/**
when qeep_mode != 0, the followed cipher table will be replaced to QEEP based ciphers:
      aes_ecb  -> qeep_ecb
      aes_ctr  -> qeep_ctr
      aes_gcm ->  qeep_gcm
 */
const EVP_CIPHER* (*_crysprOpenSSL_EVP_cipher_fnptr[][4])(void) = {
    {NULL, NULL, NULL, NULL}, // HCRYPT_CTX_MODE_CLRTXT
    {EVP_aes_128_ecb, EVP_aes_192_ecb, EVP_aes_256_ecb, EVP_aes_256_ecb}, // HCRYPT_CTX_MODE_AESECB
    {EVP_aes_128_ctr, EVP_aes_192_ctr, EVP_aes_256_ctr, EVP_aes_256_ctr}, // HCRYPT_CTX_MODE_AESCTR
    {NULL, NULL, NULL, NULL}, // HCRYPT_CTX_MODE_AESCBC
    {EVP_aes_128_gcm, EVP_aes_192_gcm, EVP_aes_256_gcm, EVP_aes_256_gcm}, // HCRYPT_CTX_MODE_AESGCM
};
const char* _qispace_provider_ciphers[][4] = {
    {NULL, NULL, NULL, NULL},                                         // HCRYPT_CTX_MODE_CLRTXT
    {"qeep_128_ecb", "qeep_192_ecb", "qeep_256_ecb", "qeep_256_ecb"}, // HCRYPT_CTX_MODE_AESECB
    {"qeep_128_ctr", "qeep_192_ctr", "qeep_256_ctr", "qeep_256_ctr"}, // HCRYPT_CTX_MODE_AESCTR
    {NULL, NULL, NULL, NULL},                                         // HCRYPT_CTX_MODE_AESCBC
    {"qeep_128_gcm", "qeep_192_gcm", "qeep_256_gcm", "qeep_256_gcm"}, // HCRYPT_CTX_MODE_AESGCM
};

static EVP_CIPHER* _fetch_EVP_cipher_qeep(int cipher_type, int idxKlen) {
    DBG_PRINT("qeep cipher name: %s \n", _qispace_provider_ciphers[cipher_type][idxKlen]);
    return EVP_CIPHER_fetch(NULL, _qispace_provider_ciphers[cipher_type][idxKlen], NULL);
}

int crysprOpenSSL_EVP_AES_SetKey(
    int                  cipher_type, /* One of HCRYPT_CTX_MODE_[CLRTXT|AESECB|AESCTR] */
    bool                 bEncrypt,    /* true Enxcrypt key, false: decrypt */
    const unsigned char* kstr,        /* key sttring*/
    size_t               kstr_len,    /* kstr len in  bytes (16, 24, or 32 bytes (for AES128, AES192, or AES256) */
    CRYSPR_AESCTX*       aes_qeep_key)           /* CRYpto Service PRovider AES Key context */
{
    DBG_PRINT("IN-1 %s: cipher_type %d, kstr_len %d \n", __func__, cipher_type, (int)kstr_len);
    DBG_PRINT("kstr: %02X%02X...%02x \n", kstr[0], kstr[1], kstr[kstr_len-1]);

    const EVP_CIPHER* cipher  = NULL;
    #ifdef _QEEP_ENABLED
    EVP_CIPHER_CTX *aes_key;
    aes_key = aes_qeep_key->evp_ctx;
    DBG_PRINT(  "  qeep_mode: %d \n", aes_qeep_key->qeep_mode);
    #else
    EVP_CIPHER_CTX *aes_key = aes_qeep_key;
    #endif


    int  idxKlen = (int)((kstr_len / 8) - 2); /* key_len index in cipher_fnptr array in [0,1,2] range */
    
    switch (cipher_type)
    {
    case HCRYPT_CTX_MODE_CLRTXT:
        return 0;
    case HCRYPT_CTX_MODE_AESECB:
        break;
    case HCRYPT_CTX_MODE_AESCTR:
#if !CRYSPR_HAS_AESCTR
        /* internal implementation of AES-CTR using crypto lib's AES-ECB */
        cipher_type = HCRYPT_CTX_MODE_AESECB;
#endif
        break;
    case HCRYPT_CTX_MODE_AESGCM:
        break;
    default:
        HCRYPT_LOG(LOG_ERR,
                   "invalid cipher type (%d). Expected: [%d..%d]\n",
                   cipher_type,
                   HCRYPT_CTX_MODE_AESECB,
                   HCRYPT_CTX_MODE_AESCTR);
        return (-1);
    }

    switch (kstr_len)
    {
    case 128 / 8:
    case 192 / 8:
    case 256 / 8:
        break;
    default:
        HCRYPT_LOG(LOG_ERR, "invalid key length (%d). Expected: 16, 24, 32\n", (int)kstr_len);
        return -1;
    }

#ifdef _QEEP_ENABLED
    if (aes_qeep_key->qeep_mode > 0) {
        cipher = _fetch_EVP_cipher_qeep(cipher_type, idxKlen);
    } else {
        cipher = _crysprOpenSSL_EVP_cipher_fnptr[cipher_type][idxKlen]();
    }
#else
    cipher = _crysprOpenSSL_EVP_cipher_fnptr[cipher_type][idxKlen]();
#endif

    if (bEncrypt)
    { /* Encrypt key */
        if (!EVP_EncryptInit_ex(aes_key, cipher, NULL, (const unsigned char *)kstr, NULL))
        {
            HCRYPT_LOG(LOG_ERR, "%s", "EVP_CipherInit_ex(kek) failed\n");
            return (-1);
        }
    }
    else
    { /* Decrypt key */
        if (!EVP_DecryptInit_ex(aes_key, cipher, NULL, (const unsigned char *)kstr, NULL))
        {
            HCRYPT_LOG(LOG_ERR, "%s", "EVP_CipherInit_ex(kek) failed\n");
            return (-1);
        }
    }

DBG_PRINT("OUT-1 %s\n", __func__);
    return (0);
}

static CRYSPR_cb* crysprOpenSSL_EVP_Open(CRYSPR_methods* cryspr, size_t max_len)
{
    DBG_PRINT("IN %s\n", __func__);
    CRYSPR_cb* cryspr_cb = crysprHelper_Open(cryspr, sizeof(*cryspr_cb), max_len);

    if (NULL == cryspr_cb)
    {
        HCRYPT_LOG(LOG_ERR, "crysprFallback_Open(%p, %zd) failed\n", cryspr, max_len);
        return (NULL);
    }
#ifndef _QEEP_ENABLED
    cryspr_cb->aes_kek = EVP_CIPHER_CTX_new();
    cryspr_cb->aes_sek[0] = EVP_CIPHER_CTX_new();
    cryspr_cb->aes_sek[1] = EVP_CIPHER_CTX_new();
#endif

#ifdef _QEEP_ENABLED
#ifdef CRYSPR2
    //DBG_PRINT("CRYSPR2 defined \n");
    CRYSPR_GETKEK(cryspr_cb) = (CRYSPR_AESCTX*) malloc(sizeof(CRYSPR_AESCTX));
    CRYSPR_GETSEK(cryspr_cb, 0) = (CRYSPR_AESCTX*) malloc(sizeof(CRYSPR_AESCTX));
    CRYSPR_GETSEK(cryspr_cb, 1) = (CRYSPR_AESCTX*) malloc(sizeof(CRYSPR_AESCTX));
#endif

    //DBG_PRINT("CRYSPR_GETKEK %p \n", CRYSPR_GETKEK(cryspr_cb));
    CRYSPR_GETKEK(cryspr_cb)->evp_ctx = EVP_CIPHER_CTX_new();
    CRYSPR_GETKEK(cryspr_cb)->qeep_mode = 0;
    CRYSPR_GETSEK(cryspr_cb, 0)->evp_ctx = EVP_CIPHER_CTX_new();
    CRYSPR_GETSEK(cryspr_cb, 0)->qeep_mode = 0;
    CRYSPR_GETSEK(cryspr_cb, 1)->evp_ctx = EVP_CIPHER_CTX_new();
    CRYSPR_GETSEK(cryspr_cb, 1)->qeep_mode = 0;

    if (prov == NULL) prov=OSSL_PROVIDER_load(NULL, "qispace_provider");
    if (prov != NULL) {
        DBG_PRINT("qispace_provider loaded \n");
        EVP_CIPHER_CTX *_QEEP_EVP_CIPHER = EVP_CIPHER_fetch(NULL, "qeep", NULL);
        if (_QEEP_EVP_CIPHER == NULL ) {
            HCRYPT_LOG(LOG_ERR, "%s", "_QEEP_EVP_CIPHER fetch failed\n");
            DBG_PRINT("_QEEP_EVP_CIPHER fetch failed from qispace_provider\n");
            //failed out in this case for qispace_provider is not correct
            return (NULL);
        }
        DBG_PRINT("  cipher qeep fetched \n");
    } else {
        DBG_PRINT("qispace_provider not found \n");
    }

#endif
DBG_PRINT("OUT %s\n", __func__);
    return (cryspr_cb);
}

static int crysprOpenSSL_EVP_Close(CRYSPR_cb* cryspr_cb)
{
    DBG_PRINT("IN %s\n", __func__);
    if (NULL != cryspr_cb)
    {
#ifndef _QEEP_ENABLED
        EVP_CIPHER_CTX_free(cryspr_cb->aes_sek[0]);
        EVP_CIPHER_CTX_free(cryspr_cb->aes_sek[1]);
        EVP_CIPHER_CTX_free(cryspr_cb->aes_kek);
#else
        EVP_CIPHER_CTX_free( CRYSPR_GETKEK(cryspr_cb)->evp_ctx);
        EVP_CIPHER_CTX_free( CRYSPR_GETSEK(cryspr_cb, 0)->evp_ctx);
        EVP_CIPHER_CTX_free(CRYSPR_GETSEK(cryspr_cb, 1)->evp_ctx);
    #ifdef CRYSPR2
        //DBG_PRINT("CRYSPR2 defined \n");
        free(CRYSPR_GETKEK(cryspr_cb));
        free(CRYSPR_GETSEK(cryspr_cb, 0));
        free(CRYSPR_GETSEK(cryspr_cb, 1));
    #endif

        if (prov != NULL) {
            OSSL_PROVIDER_unload(prov);
        }
#endif
    }
DBG_PRINT("OUT %s\n", __func__);
    return (crysprHelper_Close(cryspr_cb));
}

//#if !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP)
#if 1
int crysprOpenSSL_EVP_AES_EcbCipher(bool                 bEncrypt, /* true:encrypt, false:decrypt */
                                    CRYSPR_AESCTX*       aes_qeep_key,  /* CRYpto Service PRovider AES Key context */
                                    const unsigned char* indata, /* src (clear text if encrypt, cipher text otherwise)*/
                                    size_t               inlen,  /* indata length */
                                    unsigned char* out_txt, /* dst (cipher text if encrypt, clear text otherwise) */
                                    size_t*        outlen_p)       /* in/out dst len */
{
    DBG_PRINT("IN %s, inlen:%d, bEncrypt:%d\n", __func__, (int)inlen, (int)bEncrypt);
    HEXDUMP("indata", indata, inlen);
    EVP_CIPHER_CTX *aes_key;
    unsigned char* iv = NULL;
#ifdef _QEEP_ENABLED
    aes_key = aes_qeep_key->evp_ctx;
    // unsigned char* iv = NULL; //_QEEP_DEFAULT_IV;
#else
    aes_key = aes_qeep_key;
#endif

    int    nmore  = inlen % CRYSPR_AESBLKSZ; /* bytes in last incomplete block */
    int    nblk   = (int)(inlen / CRYSPR_AESBLKSZ + (nmore ? 1 : 0)); /* blocks including incomplete */
    size_t outsiz = (outlen_p ? *outlen_p : 0);
    int    c_len = 0, f_len = 0;
DBG_PRINT("nmore=%d, nblk=%d, outsize=%d \n", nmore, nblk, outsiz);
    (void)bEncrypt; // not needed, alreadydefined in context

    if (outsiz % CRYSPR_AESBLKSZ)
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EcbCipher() no room for PKCS7 padding");
        return (-1); /* output buf size must be a multiple of AES block size (16) */
    }
    if ((outsiz > 16) && ((int)outsiz < (nblk * CRYSPR_AESBLKSZ)))
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EcbCipher() no room for PKCS7 padding");
        return (-1); /* output buf size must have room for PKCS7 padding */
    }
    /* allows reusing of 'e' for multiple encryption cycles */
    if (!EVP_CipherInit_ex(aes_key, NULL, NULL, NULL, iv, bEncrypt))
    {
        HCRYPT_LOG(LOG_ERR, "EVP_CipherInit_ex(%p,NULL,...,-1) failed\n", aes_key);
        return -1;
    }
    if (!EVP_CIPHER_CTX_set_padding(aes_key, 0))
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_CIPHER_CTX_set_padding(%p) failed", aes_key);
        return -1;
    }

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     * cryptoPtr->cipher_in_len is the size of plain/cipher text in bytes
     */
    if (!EVP_CipherUpdate(aes_key, out_txt, &c_len, indata, (int)inlen))
    {
        HCRYPT_LOG(LOG_ERR, "EVP_CipherUpdate(%p, out, %d, in, %d) failed\n", aes_key, c_len, inlen);
        return -1;
    }
    HEXDUMP("out_txt", out_txt, c_len);
    /* update ciphertext with the final remaining bytes */
    /* Useless with pre-padding */
    f_len = 0;
    if (0 == EVP_CipherFinal_ex(aes_key, &out_txt[c_len], &f_len))
    {
#if ENABLE_HAICRYPT_LOGGING
        char szErrBuf[256];
        HCRYPT_LOG(LOG_ERR,
                   "EVP_CipherFinal_ex(ctx,&out[%d],%d)) failed: %s\n",
                   c_len,
                   f_len,
                   ERR_error_string(ERR_get_error(), szErrBuf));
#endif /*ENABLE_HAICRYPT_LOGGING*/
        return -1;
    }
#ifdef _QEEP_ENABLED
    //handling incompleting block as QEEP no ECB padding
    if ( nmore > 0 && nmore < 16 ) {
        f_len = CRYSPR_AESBLKSZ - nmore;
        DBG_PRINT("  qeep_ctx f_len: %d \n", f_len);
        memset(&out_txt[c_len], 0, f_len);
    }
#endif

    if (outlen_p != NULL) *outlen_p = nblk * CRYSPR_AESBLKSZ;
    HEXDUMP("indata", indata, inlen);
    HEXDUMP("out_txt", out_txt, c_len);
    return 0;

}
#endif /* !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP) */

int crysprOpenSSL_EVP_AES_CtrCipher(bool                 bEncrypt, /* true:encrypt, false:decrypt */
                                    CRYSPR_AESCTX*       aes_qeep_key,  /* CRYpto Service PRovider AES Key context */
                                    unsigned char*       iv,       /* iv */
                                    const unsigned char* indata,   /* src */
                                    size_t               inlen,    /* length */
                                    unsigned char*       out_txt)        /* dest */

{

    DBG_PRINT("IN %s, inlen:%d, bEncrypt:%d\n", __func__, (int)inlen, (int)bEncrypt);
    EVP_CIPHER_CTX *aes_key;

#ifdef _QEEP_ENABLED
    aes_key = aes_qeep_key->evp_ctx;
#else
    aes_key = aes_qeep_key;
#endif

    int c_len, f_len;

    (void)bEncrypt;

    /* allows reusing of 'e' for multiple encryption cycles */
    if (!EVP_CipherInit_ex(aes_key, NULL, NULL, NULL, iv, bEncrypt))  
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_CipherInit_ex() failed");
        return -1;
    }
    if (!EVP_CIPHER_CTX_set_padding(aes_key, 0))
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_CIPHER_CTX_set_padding() failed");
        return -1;
    }

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     * cryptoPtr->cipher_in_len is the size of plain/cipher text in bytes
     */
    if (!EVP_CipherUpdate(aes_key, out_txt, &c_len, indata, (int)inlen))
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_CipherUpdate() failed");
        return -1;
    }

    /* update ciphertext with the final remaining bytes */
    /* Useless with pre-padding */
    f_len = 0;
    if (0 == EVP_CipherFinal_ex(aes_key, &out_txt[c_len], &f_len))
    {
#if ENABLE_HAICRYPT_LOGGING
        char szErrBuf[256];
        HCRYPT_LOG(LOG_ERR,
                   "EVP_CipherFinal_ex(ctx,&out[%d],%d)) failed: %s\n",
                   c_len,
                   f_len,
                   ERR_error_string(ERR_get_error(), szErrBuf));
#endif /*ENABLE_HAICRYPT_LOGGING*/
        return -1;
    }
    return 0;

}

int crysprOpenSSL_EVP_AES_GCMCipher(bool                 bEncrypt, /* true:encrypt, false:decrypt */
                                    CRYSPR_AESCTX*       aes_qeep_key,  /* CRYpto Service PRovider AES Key context */
                                    unsigned char*       iv,       /* iv */
                                    const unsigned char* aad,      /* associated data */
                                    size_t               aadlen,
                                    const unsigned char* indata,   /* src */
                                    size_t               inlen,    /* length */
                                    unsigned char*       out_txt,
                                    unsigned char*       out_tag)  /* auth tag */
{
    
    DBG_PRINT("IN %s\n", __func__);
    EVP_CIPHER_CTX *aes_key;
#ifdef _QEEP_ENABLED
    aes_key = aes_qeep_key->evp_ctx;
#else
    aes_key = aes_qeep_key;
#endif
    int  c_len = 0, f_len = 0;


    /* allows reusing of 'e' for multiple encryption cycles */
    if (!EVP_CipherInit_ex(aes_key, NULL, NULL, NULL, iv, -1))
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_CipherInit_ex() failed");
        return -1;
    }
    if (!EVP_CIPHER_CTX_set_padding(aes_key, 0))
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_CIPHER_CTX_set_padding() failed");
        return -1;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (1 != EVP_CipherUpdate(aes_key, NULL, &c_len, aad, (int) aadlen))
    {
        ERR_print_errors_fp(stderr);
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_EncryptUpdate failed");
        return -1;
    }

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
     * cryptoPtr->cipher_in_len is the size of plain/cipher text in bytes
     */
    if (!EVP_CipherUpdate(aes_key, out_txt, &c_len, indata, (int) inlen))
    {
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_CipherUpdate() failed");
        return -1;
    }

    if (!bEncrypt && !EVP_CIPHER_CTX_ctrl(aes_key, EVP_CTRL_GCM_SET_TAG, HAICRYPT_AUTHTAG_MAX, out_tag)) {
        ERR_print_errors_fp(stderr);
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_EncryptUpdate failed");
        return -1;
    }

    /* update ciphertext with the final remaining bytes */
    /* Useless with pre-padding */
    f_len = 0;
    if (0 == EVP_CipherFinal_ex(aes_key, &out_txt[c_len], &f_len))
    {
#if ENABLE_HAICRYPT_LOGGING
        char szErrBuf[256];
        HCRYPT_LOG(LOG_ERR,
                   "EVP_CipherFinal_ex(ctx,&out[%d],%d)) failed: %s\n",
                   c_len,
                   f_len,
                   ERR_error_string(ERR_get_error(), szErrBuf));
#endif /*ENABLE_HAICRYPT_LOGGING*/
        return -1;
    }

    /* Get the tag if we are encrypting */
    if (bEncrypt && !EVP_CIPHER_CTX_ctrl(aes_key, EVP_CTRL_GCM_GET_TAG, HAICRYPT_AUTHTAG_MAX, out_tag))
    {
        ERR_print_errors_fp(stderr);
        HCRYPT_LOG(LOG_ERR, "%s\n", "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG) failed");
        return -1;
    }

    return 0;

}

static int _hexstring2number(char *in, unsigned char *out)
{
  char byte_val;
  int outlen = 0;
  if(!in || !out)
    return -1;

  while(*in != 0) {
    /* Compute fist half-byte */
    if(*in >= 'A' && *in <= 'F') {
      byte_val = (*in - 55)<<4;
    } else if(*in >= 'a' && *in <= 'f') {
      byte_val = (*in - 87)<<4;
    } else if(*in >= '0' && *in <= '9') {
      byte_val = (*in - 48)<<4;
    } else {
      return -1;
    }
    in++;
    if(*in == 0) {
        break;
    }
    /* Compute second half-byte */
    if(*in >= 'A' && *in <= 'F') {
      *out = (*in - 55) + byte_val;
    } else if(*in >= 'a' && *in <= 'f') {
      *out = (*in - 87) + byte_val;
    } else if(*in >= '0' && *in <= '9') {
      *out = (*in - 48) + byte_val;
    } else {
      return -1;
    }
    in++; out++;
    outlen++;
    if(!in || !out)
      return -1;
  }
  return outlen;
}

/*
 * Password-based Key Derivation Function
 */
int crysprOpenSSL_EVP_KmPbkdf2(CRYSPR_cb*     cryspr_cb,
                               char*          passwd,     /* passphrase */
                               size_t         passwd_len, /* passphrase len */
                               unsigned char* salt,       /* salt */
                               size_t         salt_len,   /* salt_len */
                               int            itr,        /* iterations */
                               size_t         key_len,    /* key_len */
                               unsigned char* out)        /* derived key */
{

DBG_PRINT("IN: %s, (pass: %s, pass_len:%d key_len:%d salt_len:%d)\n", __func__, passwd, (int)passwd_len, (int)key_len, (int)salt_len);
#ifdef _QEEP_ENABLED
    //set qeep mode according to cfg.pwd here
    int rc;
    CRYSPR_AESCTX *aes_kek = CRYSPR_GETKEK(cryspr_cb);
    if (passwd_len > 11 && strncmp("QISPACE:QK:", passwd, 11) == 0 ){
        aes_kek->qeep_mode = 2;
        rc = PKCS5_PBKDF2_HMAC_SHA1(&(passwd[11]), (int)passwd_len - 11, salt, (int)salt_len, itr, (int)key_len, out);
    } else {
        rc = PKCS5_PBKDF2_HMAC_SHA1(passwd, (int)passwd_len, salt, (int)salt_len, itr, (int)key_len, out);
    }
    DBG_PRINT("out: %02X %02X ... %02x \n", out[0], out[1], out[key_len-1]);
    return (rc == 1 ? 0 : -1);
#else
    int rc = PKCS5_PBKDF2_HMAC_SHA1(passwd, (int)passwd_len, salt, (int)salt_len, itr, (int)key_len, out);
    DBG_PRINT("out: %02X %02X ... %02x \n", out[0], out[1], out[key_len-1]);
    return (rc == 1 ? 0 : -1);
#endif

}


#if CRYSPR_HAS_AESKWRAP
int crysprOpenSSL_EVP_KmWrap(CRYSPR_cb* cryspr_cb, unsigned char* wrap, const unsigned char* sek, unsigned int seklen)
{
    DBG_PRINT("IN: %s )\n", __func__ );
    CRYSPR_AESCTX *kek = CRYSPR_GETKEK(cryspr_cb);
    return (((seklen + HAICRYPT_WRAPKEY_SIGN_SZ) == (unsigned int)AES_wrap_key(kek, NULL, wrap, sek, seklen)) ? 0 : -1);
}

int crysprOpenSSL_EVP_KmUnwrap(CRYSPR_cb*           cryspr_cb,
                               unsigned char*       sek, // Stream encrypting key
                               const unsigned char* wrap,
                               unsigned int         wraplen)
{
    DBG_PRINT("IN: %s \n", __func__);
    CRYSPR_AESCTX  *kek = CRYSPR_GETKEK(cryspr_cb); // key encrypting key
    return (((wraplen - HAICRYPT_WRAPKEY_SIGN_SZ) == (unsigned int)AES_unwrap_key(kek, NULL, sek, wrap, wraplen)) ? 0 : -1);
}
#endif /*CRYSPR_HAS_AESKWRAP*/

int crysprOpenSSL_EVP_KmWrap_Qeep(CRYSPR_cb* cryspr_cb, unsigned char* wrap, const unsigned char* sek, unsigned int seklen) {
    #if CRYSPR_HAS_AESKWRAP
        // using current WRAP
        return crysprOpenSSL_EVP_KmWrap(cryspr_cb,  wrap,  sek,  seklen);
    #else

        //fallbak using AES_ECB
        int rc = crysprFallback_AES_WrapKey(cryspr_cb,  wrap,  sek,  seklen);
        HEXDUMP("sek", sek, seklen);
        HEXDUMP("wrap", wrap, seklen+8);
        
        return (rc);
    #endif
}

int crysprOpenSSL_EVP_KmUnwrap_Qeep(CRYSPR_cb*         cryspr_cb,
                               unsigned char*       sek, // Stream encrypting key
                               const unsigned char* wrap,
                               unsigned int         wraplen) {
    #if CRYSPR_HAS_AESKWRAP
        // using current WRAP
        return crysprOpenSSL_EVP_KmUnwrap(cryspr_cb,  sek,  wrap,  wraplen);
    #else
        //fallbak using AES_ECB
        int rc = crysprFallback_AES_UnwrapKey(cryspr_cb,  sek,  wrap,  wraplen);
        HEXDUMP("wrap", wrap, wraplen);
        HEXDUMP("sek", sek, wraplen-8);
        return (rc);
    #endif
}

static int crysprOpenSSL_EVP_KmSetKey_Qeep(CRYSPR_cb *cryspr_cb, bool bWrap, const unsigned char *kek, size_t kek_len)
{
DBG_PRINT("IN: %s  \n", __func__ );
    CRYSPR_AESCTX *aes_kek = CRYSPR_GETKEK(cryspr_cb);
#ifdef _QEEP_ENABLED
    DBG_PRINT("     aes_kek-qeep_mode: %d  \n",aes_kek->qeep_mode );
    if (aes_kek->qeep_mode > 0 ) {
        //for qeep, using QEEP ECB
        if (cryspr_cb->cryspr->aes_set_key(HCRYPT_CTX_MODE_AESECB, bWrap, kek, kek_len, aes_kek)) {
            HCRYPT_LOG(LOG_ERR, "aes_set_%s_key(kek) failed\n", bWrap? "encrypt": "decrypt");
            return(-1);
        }
        return (0);
    }
#endif
    //for aes, fallback using aes_ecb 
    if (cryspr_cb->cryspr->aes_set_key(HCRYPT_CTX_MODE_AESECB, bWrap, kek, kek_len, aes_kek)) {
        HCRYPT_LOG(LOG_ERR, "aes_set_%s_key(kek) failed\n", bWrap? "encrypt": "decrypt");
        return(-1);
    }
    return(0);
}

static int crysprOpenSSL_EVP_MsSetKey_Qeep(CRYSPR_cb *cryspr_cb, hcrypt_Ctx *ctx, const unsigned char *key, size_t key_len)
{
DBG_PRINT("IN: %s  \n", __func__ );

    CRYSPR_AESCTX *aes_sek = CRYSPR_GETSEK(cryspr_cb, hcryptCtx_GetKeyIndex(ctx)); /* Ctx tells if it's for odd or even key */
    // set qeep mode according to cfg.pwd here
    if (ctx->cfg.pwd_len > 11 && strncmp("QISPACE:QK:", ctx->cfg.pwd, 11) == 0 ){
        DBG_PRINT("   pwd: %s \n", ctx->cfg.pwd);
        aes_sek->qeep_mode = 1;
    }
    DBG_PRINT("   ctx->flag:%d, ctx->mode:%d \n", (ctx->flags & HCRYPT_CTX_F_ENCRYPT),ctx->mode);
    if (ctx->mode == HCRYPT_CTX_MODE_AESGCM) {   /* AES GCM mode */
        if (cryspr_cb->cryspr->aes_set_key(HCRYPT_CTX_MODE_AESGCM, (ctx->flags & HCRYPT_CTX_F_ENCRYPT) != 0, key, key_len, aes_sek)) {
            HCRYPT_LOG(LOG_ERR, "%s", "CRYSPR->set_encrypt_key(sek) failed\n");
            return(-1);
        }
    } else if ((ctx->mode == HCRYPT_CTX_MODE_AESCTR)) { 
        #ifdef _QEEP_ENABLED
        if (aes_sek->qeep_mode > 0) {
            //QEEP CTR enc and dec key are same as CBC
            if (cryspr_cb->cryspr->aes_set_key(HCRYPT_CTX_MODE_AESCTR, (ctx->flags & HCRYPT_CTX_F_ENCRYPT) != 0, key, key_len, aes_sek)) {
                HCRYPT_LOG(LOG_ERR, "%s", "CRYSPR->set_encrypt_key(sek) failed\n");
                return(-1);
            }
            return (0);
        }
        #endif
          /* CTR mode decrypts using encryption methods */
        if (cryspr_cb->cryspr->aes_set_key(HCRYPT_CTX_MODE_AESCTR, true, key, key_len, aes_sek)) {
            HCRYPT_LOG(LOG_ERR, "%s", "CRYSPR->set_encrypt_key(sek) failed\n");
            return(-1);
        }
    } else {                                       /*Default using CTR*/
        if (cryspr_cb->cryspr->aes_set_key(HCRYPT_CTX_MODE_AESCTR, (ctx->flags & HCRYPT_CTX_F_ENCRYPT) != 0, key, key_len, aes_sek)) {
            HCRYPT_LOG(LOG_ERR, "%s", "CRYSPR->set_decrypt_key(sek) failed\n");
            return(-1);
        }
    }
    return(0);
}

static CRYSPR_methods crysprOpenSSL_EVP_methods;

CRYSPR_methods* crysprOpenSSL_EVP(void)
{
    DBG_PRINT("IN: %s \n", __func__);
    if (NULL == crysprOpenSSL_EVP_methods.open)
    {
        crysprInit(&crysprOpenSSL_EVP_methods); // Default/fallback methods

        crysprOpenSSL_EVP_methods.prng = crysprOpenSSL_EVP_Prng;
        //--CryptoLib Primitive API-----------------------------------------------

        crysprOpenSSL_EVP_methods.aes_set_key = crysprOpenSSL_EVP_AES_SetKey;
#if CRYSPR_HAS_AESCTR

        crysprOpenSSL_EVP_methods.aes_ctr_cipher = crysprOpenSSL_EVP_AES_CtrCipher;
#endif
        crysprOpenSSL_EVP_methods.aes_gcm_cipher = crysprOpenSSL_EVP_AES_GCMCipher;
//#if !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP)
#if 1
        /* AES-ECB only required if cryspr has no AES-CTR and no AES KeyWrap */
        /* OpenSSL has both AESCTR and AESKWRP and the AESECB wrapper is only used
           to test the falback methods */
        crysprOpenSSL_EVP_methods.aes_ecb_cipher = crysprOpenSSL_EVP_AES_EcbCipher;
#endif
#if !CRYSPR_HAS_PBKDF2
        crysprOpenSSL_EVP_methods.sha1_msg_digest = NULL; // Required to use eventual default/fallback KmPbkdf2
#endif

        //--Crypto Session API-----------------------------------------
        crysprOpenSSL_EVP_methods.open  = crysprOpenSSL_EVP_Open;
        crysprOpenSSL_EVP_methods.close = crysprOpenSSL_EVP_Close;
        //--Keying material (km) encryption

#if CRYSPR_HAS_PBKDF2
        crysprOpenSSL_EVP_methods.km_pbkdf2 = crysprOpenSSL_EVP_KmPbkdf2;
#else
#error There is no default/fallback method for PBKDF2
#endif
        crysprOpenSSL_EVP_methods.km_setkey  = crysprOpenSSL_EVP_KmSetKey_Qeep;
//#if CRYSPR_HAS_AESKWRAP
        crysprOpenSSL_EVP_methods.km_wrap   = crysprOpenSSL_EVP_KmWrap_Qeep;
        crysprOpenSSL_EVP_methods.km_unwrap = crysprOpenSSL_EVP_KmUnwrap_Qeep;
//#endif

        //--Media stream (ms) encryption
        crysprOpenSSL_EVP_methods.ms_setkey  = crysprOpenSSL_EVP_MsSetKey_Qeep;
        //	crysprOpenSSL_EVP_methods.ms_encrypt =
        //	crysprOpenSSL_EVP_methods.ms_decrypt =
    }
    DBG_PRINT("OUT: %s \n", __func__);
    return (&crysprOpenSSL_EVP_methods);
}
