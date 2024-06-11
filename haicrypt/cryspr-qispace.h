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

#ifndef CRYSPR_QISPACE_H
#define CRYSPR_QISPACE_H
#include "qispace_qeep.h"

/* Define CRYSPR_HAS_AESCTR to 1 if this CRYSPR has AESCTR cipher mode
*/
#define CRYSPR_HAS_AESCTR 1

/* Define CRYSPR_HAS_AESGCM to 1 if this CRYSPR has AES GCM cipher mode.
*/
#define CRYSPR_HAS_AESGCM 1

// Force internal AES-WRAP (using AES-ECB) 
#define CRYSPR_HAS_AESKWRAP 0


/* Define CRYSPR_HAS_PBKDF2 to 1 if this CRYSPR has SHA1-HMAC Password-based Key Derivaion Function 2
*/
#define CRYSPR_HAS_PBKDF2 1 

/*
#define CRYSPR_AESCTX to the CRYSPR specifix AES key context object.
This type reserves room in the CRYPSPR control block for Haicrypt KEK and SEK
It is set from hte keystring through CRYSPR_methods.aes_set_key and passed
to CRYSPR_methods.aes_*.
*/
typedef QP_Handle CRYSPR_AESCTX; /* CRYpto Service PRovider AES key context */
// Here CRYSPR_AESCTX is QEEP key object with QiSpace

struct tag_CRYSPR_methods* crysprQiSpace(void);

#endif /* CRYSPR_QISPACE_H */
