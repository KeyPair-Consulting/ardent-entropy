/* ************************************************************************************************
 * Copyright (C) 2022-2026 Symbiotic Systems Research, LLC
 * All Rights Reserved * Proprietary and confidential
 * 
 * The methods and techniques described herein are considered 
 * trade secrets and/or confidential. Reproduction or distribution, 
 * in whole or in part, is forbidden except by express written 
 * permission of Symbiotic Systems Research, LLC.
 * Please contact <info@symsysresearch.com> for licensing information.
 * 
 * NO WARRANTY, EXPLICIT OR IMPLICIT, IS PROVIDED.
 * In no event shall the author be liable for any claim or damages.
 * 
 * Author: Randall Steck
 * ***********************************************************************************************/

/* ATTENTION:
 * This file contains the "public" names of the variables from your provider's
 * configuration file. It should be put in a public include location so your 
 * calling applications can reference these names.
 */

#ifndef ARDENT_NAMES_OPTEST_H
#define ARDENT_NAMES_OPTEST_H
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#define ENV_OPTEST_RBG2_OVERFLOW      "ARDENT_OPTEST_RBG2_OVERFLOW"

#define ENV_OPTEST_RBG2_GATHER        "ARDENT_OPTEST_RBG2_GATHER"

#define ENV_OPTEST_SEED_JITTER_NEW    "ARDENT_OPTEST_SEED_JITTER_NEW"
#define ENV_OPTEST_SEED_JITTER_GATHER "ARDENT_OPTEST_SEED_JITTER_GATHER"
#define ENV_OPTEST_SEED_JITTER_FATAL  "ARDENT_OPTEST_SEED_JITTER_FATAL"

#define ENV_OPTEST_SEED_RDSEED_NEW     "ARDENT_OPTEST_SEED_RDSEED_NEW"
#define ENV_OPTEST_SEED_RDSEED_GATHER  "ARDENT_OPTEST_SEED_RDSEED_GATHER"
#define ENV_OPTEST_SEED_RDSEED_FATAL   "ARDENT_OPTEST_SEED_RDSEED_FATAL"

#define ENV_OPTEST_SEED_RDRAND_NEW     "ARDENT_OPTEST_SEED_RDRAND_NEW"
#define ENV_OPTEST_SEED_RDRAND_GATHER  "ARDENT_OPTEST_SEED_RDRAND_GATHER"
#define ENV_OPTEST_SEED_RDRAND_FATAL   "ARDENT_OPTEST_SEED_RDRAND_FATAL"

#define ENV_OPTEST_SEED_OSRAND_NEW     "ARDENT_OPTEST_SEED_OSRADN_NEW"
#define ENV_OPTEST_SEED_OSRAND_GATHER  "ARDENT_OPTEST_SEED_OSRAND_GATHER"
#define ENV_OPTEST_SEED_OSRAND_FATAL   "ARDENT_OPTEST_SEED_OSRAND_FATAL"

#define ENV_OPTEST_SEED_EXTERN_NEW    "ARDENT_OPTEST_SEED_EXTERN_NEW"
#define ENV_OPTEST_SEED_EXTERN_GATHER "ARDENT_OPTEST_SEED_EXTERN_GATHER"
#define ENV_OPTEST_SEED_EXTERN_FATAL  "ARDENT_OPTEST_SEED_EXTERN_FATAL"

#define ENV_OPTEST_KAT_FAIL_HKDF      "ENV_OPTEST_KAT_FAIL_HKDF"
#define ENV_OPTEST_KAT_FAIL_SNMP      "ENV_OPTEST_KAT_FAIL_SNMP"
#define ENV_OPTEST_KAT_FAIL_SRTP      "ENV_OPTEST_KAT_FAIL_SRTP"
#define ENV_OPTEST_KAT_FAIL_IKE       "ENV_OPTEST_KAT_FAIL_IKE"

#ifdef __cplusplus
}
#endif
#endif /* ARDENT_NAMES_OPTEST_H */
