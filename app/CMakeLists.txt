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
#  Utility
# ##################################################################################################

IF (utility)
    # Set project source files
    SET  (APP_utility_sources keypair_utility.c)
    LIST (APPEND APP_utility_sources ../source/kpep_internal.c)
    LIST (APPEND APP_utility_sources ../source/crypto/sha2.c ../source/crypto/hmac.c)

    ADD_EXECUTABLE         (APP_utility ${APP_utility_sources})
    SET_TARGET_PROPERTIES  (APP_utility PROPERTIES OUTPUT_NAME "keypair_utility")

    TARGET_LINK_LIBRARIES  (APP_utility PRIVATE KPEP_provider)
    TARGET_LINK_LIBRARIES  (APP_utility PRIVATE ${OPENSSL_LIB})
ENDIF (utility)

IF (rand)
    # Set project source files
    SET  (APP_rand_sources keypair_rand.c)

    ADD_EXECUTABLE         (APP_rand ${APP_rand_sources})
    SET_TARGET_PROPERTIES  (APP_rand PROPERTIES OUTPUT_NAME "keypair_rand")

    TARGET_LINK_LIBRARIES  (APP_rand PRIVATE KPEP_provider)
    TARGET_LINK_LIBRARIES  (APP_rand PRIVATE ${OPENSSL_LIB})
ENDIF (rand)


