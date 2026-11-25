# ##################################################################################################
# Copyright (C) 2023-2026 Symbiotic Systems Research, LLC
# All Rights Reserved * Proprietary and confidential
# 
# The methods and techniques described herein are considered 
# trade secrets and/or confidential. Reproduction or distribution, 
# in whole or in part, is forbidden except by express written 
# permission of Symbiotic Systems Research, LLC.
# Please contact <info@symsysresearch.com> for licensing information.
# 
# NO WARRANTY, EXPLICIT OR IMPLICIT, IS PROVIDED.
# In no event shall the author be liable for any claim or damages.
# 
# Author: Randall Steck
# ##################################################################################################

# ##################################################################################################
# ARDent Utility
# ##################################################################################################

if (tests)
    # Set project source files
    SET  (APP_test_ringbuffer_sources test_ringbuffer.c)
    LIST (APPEND APP_test_ringbuffer_sources ../source/seeding/ringbuffer.c)
    LIST (APPEND APP_test_ringbuffer_sources ../source/ardent_internal.c)

    ADD_EXECUTABLE         (APP_test_ringbuffer ${APP_test_ringbuffer_sources})
    SET_TARGET_PROPERTIES  (APP_test_ringbuffer PROPERTIES OUTPUT_NAME "test_ringbuffer")
    TARGET_LINK_LIBRARIES  (APP_test_ringbuffer PRIVATE ${OPENSSL_LIB})

    # Multi-threaded OpenSSL randomness stress tester using RAND_bytes_ex(), ARDent-SEED, and HMAC-DRBG.
    ADD_EXECUTABLE         (APP_rand_stress rand_stress.c)
    SET_TARGET_PROPERTIES  (APP_rand_stress PROPERTIES OUTPUT_NAME "rand_stress")
    TARGET_LINK_LIBRARIES  (APP_rand_stress PRIVATE ${OPENSSL_LIB})

    # Runtime debug IPC dynamic reconfiguration tester
    ADD_EXECUTABLE         (APP_test_runtime_config test_runtime_config.c)
    SET_TARGET_PROPERTIES  (APP_test_runtime_config PROPERTIES OUTPUT_NAME "test_runtime_config")
    TARGET_LINK_LIBRARIES  (APP_test_runtime_config PRIVATE ${OPENSSL_LIB})
endif (tests)
