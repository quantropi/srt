/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2024 Quantropi Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

/*****************************************************************************
written by
   Quantropi Inc.

   2024-06-03 (Dafu)
        QiSpace QEEP Encryption CRYSPR/4SRT (Quantum Safe Encryption Service for SRT).
*****************************************************************************/

#include "hcrypt.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "cryspr-qispace.h"
#include "qispace_pqrnd.h"

//#define DEBUG

#ifdef DEBUG
#define DBG_PRINT(...) printf(__VA_ARGS__)
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


#define CIPHER "qispace_qeep"
#define DEFAULT_QEEP_KEY_SIZE           54
#define DEFAULT_QRAND_SEED_LEN         DEFAULT_QEEP_KEY_SIZE


static char DEFAULT_QEEP_KEY[DEFAULT_QEEP_KEY_SIZE] = {0x01,0xE8,0xE8,0x68,0x30,0xEF,0xC1,0xC6,0x55,0x9D,0x31,0x5F,0xD6,0x35,0xBD,0x7E,0x59,0xEA,0xA5,0xA0,0xA9,0x51,0x00,0xC5,0xD0,0xA2,0x43,0x19,0x72,0xEE,0x7F,0x8C,0x08,0x69,0xD4,0x7D,0xF2,0x16,0x79,0x4E,0xCF,0x49,0x37,0x4B,0x40,0x82,0x30,0x71,0xE7,0x83,0x6C,0x8F,0x26,0x22};
static pQrnd_Handle qrnd_handle = NULL;

// typedef struct tag_crysprQiSpace_cb
// {
//     CRYSPR_cb ccb;
//     /* Add cryptolib specific data here */
// } crysprQiSpace_cb;


extern QEEP_RET QSC_qeep_key_create(pQrnd_Handle QSC, uint8_t *qe, int32_t qe_len, int32_t qkFlag, int32_t req_qk_len, uint8_t *qk_out, int32_t *qk_out_len);

static CRYSPR_cb* crysprQiSpace_Open(CRYSPR_methods* cryspr, size_t max_len)
{

    CRYSPR_cb* cryspr_cb = NULL;

DBG_PRINT("IN %s\n", __func__);

DBG_PRINT("sizeof(*cryspr_cb): %zd, max_len: %zd \n", sizeof(*cryspr_cb), max_len);
    cryspr_cb = crysprHelper_Open(cryspr, sizeof(*cryspr_cb), max_len);
    if (NULL == cryspr_cb)
    {
        HCRYPT_LOG(LOG_ERR, "crysprHelper_Open(%p, %zd) failed\n", cryspr, max_len);
        return (NULL);
    }
    CRYSPR_GETKEK(cryspr_cb) = (CRYSPR_AESCTX*) malloc(sizeof(CRYSPR_AESCTX));
    CRYSPR_GETSEK(cryspr_cb, 0) = (CRYSPR_AESCTX*) malloc(sizeof(CRYSPR_AESCTX));
    CRYSPR_GETSEK(cryspr_cb, 1) = (CRYSPR_AESCTX*) malloc(sizeof(CRYSPR_AESCTX));
    if (NULL == CRYSPR_GETKEK(cryspr_cb) || NULL == CRYSPR_GETSEK(cryspr_cb, 0) || NULL == CRYSPR_GETSEK(cryspr_cb, 1)) {
        HCRYPT_LOG(LOG_ERR, "KEK, SEK[] malloc failed\n");
        return (NULL);
    }
    DBG_PRINT("kek: %p, SEK0: %p, SEK1: %p\n", (CRYSPR_GETKEK(cryspr_cb)), (CRYSPR_GETSEK(cryspr_cb, 0)), (CRYSPR_GETSEK(cryspr_cb, 1)));
    if (QP_init(CRYSPR_GETKEK(cryspr_cb)) != QEEP_OK  || QP_init(CRYSPR_GETSEK(cryspr_cb, 0)) != QEEP_OK || QP_init(CRYSPR_GETSEK(cryspr_cb, 1))!= QEEP_OK) {
        HCRYPT_LOG(LOG_ERR, "QP_init failed\n");
        free(CRYSPR_GETKEK(cryspr_cb));
        free(CRYSPR_GETSEK(cryspr_cb, 0));
        free(CRYSPR_GETSEK(cryspr_cb, 1));
        return (NULL);
    }
    // We may need to load key for KEK and SEK here

DBG_PRINT("OUT %s\n", __func__);
    return (cryspr_cb);
}

static int crysprQiSpace_Close(CRYSPR_cb* cryspr_cb)
{
DBG_PRINT("IN %s, cryspr_cb: %p \n", __func__, cryspr_cb);

DBG_PRINT("kek: %p, SEK0: %p, SEK1: %p\n", (CRYSPR_GETKEK(cryspr_cb)), (CRYSPR_GETSEK(cryspr_cb, 0)), (CRYSPR_GETSEK(cryspr_cb, 1)));

    if (NULL != cryspr_cb)
    {
     if (NULL != CRYSPR_GETKEK(cryspr_cb) && NULL != CRYSPR_GETSEK(cryspr_cb, 0) && NULL != CRYSPR_GETSEK(cryspr_cb, 1) ) {
        QP_close(*(CRYSPR_GETKEK(cryspr_cb)));   
        QP_close(*(CRYSPR_GETSEK(cryspr_cb, 0))); 
        QP_close(*(CRYSPR_GETSEK(cryspr_cb, 1))); 
        free(CRYSPR_GETKEK(cryspr_cb));
        free(CRYSPR_GETSEK(cryspr_cb, 0));
        free(CRYSPR_GETSEK(cryspr_cb, 1));
     }
    }
    DBG_PRINT("qrnd_handle: %p\n", qrnd_handle);
    if (qrnd_handle != NULL) {
        pQrndClose(qrnd_handle);
        qrnd_handle = NULL;
    }

DBG_PRINT("OUT %s\n", __func__);
    return (crysprHelper_Close(cryspr_cb));
}

int crysprQiSpace_Qeep_Prng(unsigned char* rn, int len)
{
    unsigned char qrnd_seed[DEFAULT_QRAND_SEED_LEN];
DBG_PRINT("IN- %s, rn_len: %d \n", __func__, len);

#if 0
    for (int i=0; i < len; i++) {
        rn[i] = "1";
    }
    return (0);
#endif

    if (qrnd_handle == NULL ) {
        if (pQrndInit(&qrnd_handle) != QEEP_OK )  {
            HCRYPT_LOG(LOG_ERR, "crysprQiSpace_Open, pQrndInit failed\n");
            return (-1);
        }
        srand(time(0));
        for(int i = 0; i< DEFAULT_QRAND_SEED_LEN; i++)
            qrnd_seed[i] = rand()&0xff;
        if (pQrndSeed(qrnd_handle, qrnd_seed, DEFAULT_QRAND_SEED_LEN) !=  QEEP_OK )  {
            HCRYPT_LOG(LOG_ERR, "crysprQiSpace_Open, pQrndSeed failed\n");
            pQrndClose(qrnd_handle);
            return (-1);
        }
    }

    if (pQrndRnd(qrnd_handle, rn, len) == QEEP_OK) {
        HEXDUMP("rn", rn, len);
        return (0);
    }
    return (-1);
}

//qk should be freed by caller
static uint8_t* keyStr2QeepKey(uint8_t * ks, int32_t ks_l,  int32_t *qk_out_len) {
       /**convert kstr to QEEP KEY */
        pQrnd_Handle qHandle = NULL;
        uint8_t *ks_t = (uint8_t*)calloc(ks_l + 16, sizeof(char));
        uint8_t *qk_out= (uint8_t*)calloc(ks_l + 32, sizeof(char));
        DBG_PRINT("IN- %s \n", __func__ );

        //memcpy(&ks_t[16], ks, ks_l);
        QP_init(&qHandle);
        
        QSC_qeep_key_create(qHandle, ks, (int32_t)(ks_l), 0, (int32_t)(ks_l), qk_out, qk_out_len);

        HEXDUMP("ks", ks, ks_l);
        HEXDUMP("qk", qk_out, *qk_out_len);
        QP_close(qHandle);
        free(ks_t);
        return qk_out;
}

int crysprQispace_Qeep_SetKey(
    int                  cipher_type, /* One of HCRYPT_CTX_MODE_[CLRTXT|AESECB|AESCTR] */
    bool                 bEncrypt,    /* true Encrypt key, false: decrypt */
    const unsigned char* kstr,        /* key sttring*/
    size_t               kstr_len,    /* kstr len in  bytes (16, 24, or 32 bytes (for AES128, AES192, or AES256) */
    CRYSPR_AESCTX*       qeep_handle)           /* CRYpto Service PRovider Key context */
{

    int ret;
    DBG_PRINT("IN-1 %s, cipher_type %d \n", __func__, cipher_type);
    DBG_PRINT("qeep_handle: %p \n", qeep_handle);
    // For QEEP, key is same for all cipher type
    // if kstr is QEEP KEY, load it directly
    // otherwise create QEEP KEY from kstr using KDF2

    if (qeep_handle == NULL ) {
            HCRYPT_LOG(LOG_ERR, "%s", "qeep_handle is NULL\n");
            return (-1);
    }
    DBG_PRINT("*qeep_handle: %p, bEncrypt: %d \n", *qeep_handle, bEncrypt);
    if (*qeep_handle == NULL ) {
        DBG_PRINT("*qeep_handle is NULL\n");
        if (QP_init(qeep_handle) != QEEP_OK ){
            HCRYPT_LOG(LOG_ERR, "%s", "QP_init qeep_handle failed\n");
            return (-1);
        }
    }

    //load default iv
    QP_iv_set(*qeep_handle, (uint8_t *)&DEFAULT_QEEP_KEY[1], 16);
    ret=QP_qeep_key_load(*qeep_handle, (uint8_t *)kstr, (int32_t)kstr_len);
    if(ret != QEEP_OK){
        int32_t qk_out_len = 0;
        uint8_t *qk_out = keyStr2QeepKey((uint8_t *)kstr, (int32_t)kstr_len, &qk_out_len);
        ret=QP_qeep_key_load(*qeep_handle, qk_out, qk_out_len);
        if (qk_out != NULL ) free(qk_out);
        if(ret != QEEP_OK) {
            DBG_PRINT("   QP_qeep_key_load after qeep_key_create fail %d ! \n", ret );
            return -1;
        }
    }
    DBG_PRINT("OUT-1 %s\n", __func__);
    return (0);
}

//#if !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP)

int crysprQiSpace_Qeep_EcbCipher(bool                    bEncrypt, /* true:encrypt, false:decrypt */
                                    CRYSPR_AESCTX*       qeep_handle,  /* CRYpto Service PRovider AES Key context */
                                    const unsigned char* indata, /* src (clear text if encrypt, cipher text otherwise)*/
                                    size_t               inlen,  /* indata length */
                                    unsigned char*       out_txt, /* dst (cipher text if encrypt, clear text otherwise) */
                                    size_t*              outlen_p)       /* in/out dst len */
{

    DBG_PRINT("IN %s\n", __func__);

    QP_iv_set(*qeep_handle, (uint8_t *)&DEFAULT_QEEP_KEY[1], 16);
    if (bEncrypt) {
        QP_encrypt(*qeep_handle, (uint8_t *)indata, (int32_t)inlen,  (uint8_t *)out_txt);
    } else {
        QP_decrypt(*qeep_handle, (uint8_t *)indata, (int32_t)inlen,  (uint8_t *)out_txt);
    }

    if (outlen_p != NULL) *outlen_p = inlen;
     DBG_PRINT("OUT %s\n", __func__);
    return 0;

}
//#endif /* !(CRYSPR_HAS_AESCTR && CRYSPR_HAS_AESKWRAP) */

int crysprQiSpace_Qeep_CtrCipher(bool                    bEncrypt, /* true:encrypt, false:decrypt */
                                    CRYSPR_AESCTX*       qeep_handle,  /* CRYpto Service PRovider AES Key context */
                                    unsigned char*       iv,       /* iv */
                                    const unsigned char* indata,   /* src */
                                    size_t               inlen,    /* length */
                                    unsigned char*       out_txt)        /* dest */

{
    DBG_PRINT("IN %s\n", __func__);
    DBG_PRINT("qeep_handle: %p, *qeep_handle: %p, inlen: %ld, bEncrypt: %d \n", qeep_handle, *qeep_handle, inlen, bEncrypt);
    QP_iv_set(*qeep_handle, iv, 16);  //CTR reset IV 
    HEXDUMP("iv", iv, 16);
    if (bEncrypt) {
        QP_encrypt(*qeep_handle, (uint8_t *)indata, (int32_t)inlen,  (uint8_t *)out_txt);
    } else {
        QP_decrypt(*qeep_handle, (uint8_t *)indata, (int32_t)inlen,  (uint8_t *)out_txt);
    }

    DBG_PRINT("OUT %s\n", __func__);
    return (0);
}

int crysprQiSpace_Qeep_GCMCipher(bool                    bEncrypt, /* true:encrypt, false:decrypt */
                                    CRYSPR_AESCTX*       qeep_handle,  /* CRYpto Service PRovider AES Key context */
                                    unsigned char*       iv,       /* iv */
                                    const unsigned char* aad,      /* associated data */
                                    size_t               aadlen,
                                    const unsigned char* indata,   /* src */
                                    size_t               inlen,    /* length */
                                    unsigned char*       out_txt,
                                    unsigned char*       out_tag)  /* auth tag */
{

    // simulatored GCM interface, 
    //out_tag is 16 byte, stub implement here
    int i;
DBG_PRINT("IN %s\n", __func__);
    if (aad != NULL && out_tag != NULL ) {
        memcpy(out_tag, iv, 16);
        for (i =0; i< (int)aadlen; i++) out_tag[0] = out_tag[0] ^ aad[i];
    }
    QP_iv_set(*qeep_handle, (uint8_t*)iv, 16);
    if (bEncrypt) {
        QP_encrypt(*qeep_handle, (uint8_t *)indata, (int32_t)inlen,  (uint8_t *)out_txt);
        //out_tag[0] = out_tag[0] ^indata[inlen-1];
    } else {
        QP_decrypt(*qeep_handle, (uint8_t *)indata, (int32_t)inlen,  (uint8_t *)out_txt);
        //out_tag[0] = out_tag[0] ^out_txt[inlen-1];
    }

DBG_PRINT("OUT %s\n", __func__);
    return (0);
}

/*
 * Password-based Key Derivation Function
 */
int crysprQiSpace_KmPbkdf2(CRYSPR_cb*     cryspr_cb,
                               char*          passwd,     /* passphrase */
                               size_t         passwd_len, /* passphrase len */
                               unsigned char* salt,       /* salt */
                               size_t         salt_len,   /* salt_len */
                               int            itr,        /* iterations */
                               size_t         key_len,    /* key_len */
                               unsigned char* out)        /* derived key */
{
    // QEEP based KDF2
    (void*) (cryspr_cb);

    unsigned char *key_t;
    uint8_t *qk;
    int32_t qk_len;
    int i, j;

    QP_Handle qhandle;
    
DBG_PRINT("IN: %s, (pass: %s, pass_len:%d key_len:%d salt_len:%d)\n", __func__, passwd, (int)passwd_len, (int)key_len, (int)salt_len);
HEXDUMP("salt", salt, salt_len);
#if 0
    memset(out, 0,  key_len);
    memcpy(out, passwd,passwd_len);
    return (0);
#endif

    key_t = (unsigned char *)calloc(key_len, sizeof(char));
    for (i =0, j=0; i< (int)key_len; i++) {
        key_t[i] = salt[j];
        j++;
        if (j >= (int)salt_len) j =0;
    }
    if(key_len < salt_len) {
        j = 0;
        for (i = (int)(salt_len -key_len); i< (int)salt_len; i++  ) {
            key_t[j] ^= salt[i];
            j++;
            if (j >= (int)key_len) j = 0;
        }
    }
    QP_init(&qhandle);
    qk = keyStr2QeepKey((uint8_t *)passwd, (int32_t)passwd_len,  &qk_len );

    QP_qeep_key_load_en(qhandle, qk, qk_len);
    free(qk);

    QP_iv_set(qhandle, (uint8_t *)&DEFAULT_QEEP_KEY[1], 16);
    for (i = 0; i < itr; i ++) {
        QP_encrypt(qhandle, key_t, key_len, out);
        memcpy(key_t, out, key_len);
    }
   QP_close(qhandle);
   free(key_t);
   HEXDUMP("key", out, key_len);
  return(0);
}



int crysprQiSpace_KmWrap(CRYSPR_cb* cryspr_cb, unsigned char* wrap, const unsigned char* sek, unsigned int seklen)
{   //out_len = sek_len + 8 according to https://www.ietf.org/rfc/rfc3394.txt
    DBG_PRINT("IN: %s\n", __func__ );
    uint8_t iv[16]; //only 8 bytes are used 
    QP_Handle*       kek= CRYSPR_GETKEK(cryspr_cb); // key encrypting key
    crysprQiSpace_Qeep_Prng(iv, 16);
    memcpy(iv, &iv[8], 8);
    memcpy(wrap, iv, 8);
    QP_iv_set(*kek,(uint8_t *) iv, 16);
    QP_encrypt(*kek, (uint8_t *)sek, (int32_t)seklen, (uint8_t *)(&wrap[8]));
    DBG_PRINT("kek: %p \n", *kek  );
    HEXDUMP("sek", sek,seklen);
    HEXDUMP("wrap", wrap,seklen + 8);
    return 0;
}

int crysprQiSpace_KmUnwrap(CRYSPR_cb*           cryspr_cb,
                               unsigned char*       sek, // Stream encrypting key
                               const unsigned char* wrap,
                               unsigned int         wraplen)
{
    DBG_PRINT("IN: %s\n", __func__ );
    QP_Handle*       kek= CRYSPR_GETKEK(cryspr_cb); // key encrypting key
    uint8_t iv[16];
    memcpy(iv, wrap, 8);
    memcpy(&(iv[8]), wrap, 8);
    QP_iv_set(*kek, (uint8_t *)iv, 16);
    QP_decrypt(*kek, (uint8_t *)(&wrap[8]), (int32_t)(wraplen-8), (uint8_t *)sek);
    DBG_PRINT("kek: %p\n", *kek  );
    HEXDUMP("wrap", wrap,wraplen);
    HEXDUMP("sek", sek,wraplen-8);
    return 0;
}


static CRYSPR_methods crysprQiSpace_methods;

CRYSPR_methods* crysprQiSpace(void)
{
    if (NULL == crysprQiSpace_methods.open)
    {
        crysprInit(&crysprQiSpace_methods); // Default/fallback methods
        //QEEP is Quantum safe cipher and compitable with AES
        crysprQiSpace_methods.prng = crysprQiSpace_Qeep_Prng;
        crysprQiSpace_methods.aes_set_key = crysprQispace_Qeep_SetKey; 
        crysprQiSpace_methods.aes_ctr_cipher = crysprQiSpace_Qeep_CtrCipher;
        crysprQiSpace_methods.aes_gcm_cipher = crysprQiSpace_Qeep_GCMCipher;
        crysprQiSpace_methods.aes_ecb_cipher = crysprQiSpace_Qeep_EcbCipher;

        crysprQiSpace_methods.sha1_msg_digest = NULL; // Required to use eventual default/fallback KmPbkdf2


        crysprQiSpace_methods.km_pbkdf2 = crysprQiSpace_KmPbkdf2;

        //--Crypto Session API-----------------------------------------
        crysprQiSpace_methods.open  = crysprQiSpace_Open;
        crysprQiSpace_methods.close = crysprQiSpace_Close;
        //--Keying material (km) encryption
        //crysprQiSpace_methods.km_setkey  = NULL;
        #if CRYSPR_HAS_AESKWRAP
        crysprQiSpace_methods.km_wrap   = crysprQiSpace_KmWrap;
        crysprQiSpace_methods.km_unwrap = crysprQiSpace_KmUnwrap;
        #endif

    }
    return (&crysprQiSpace_methods);
}
