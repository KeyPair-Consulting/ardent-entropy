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
# File List
# ##################################################################################################

# Provider and FIPS-critical code
SET  (ARDent_sources ardent_provider.c ardent_self_test.c)

# Core functionality
LIST (APPEND ARDent_sources ardent_internal.c ardent_integrity.c ardent_error.c)
LIST (APPEND ARDent_sources ardent_seeding.c ardent_cpuinfo.c ardent_bio.c)

# Subsystems added by 'objects' instead of static libraries
LIST (APPEND ARDent_sources $<TARGET_OBJECTS:ARDent_crypto>)
LIST (APPEND ARDent_sources $<TARGET_OBJECTS:ARDent_thread>)
LIST (APPEND ARDent_sources $<TARGET_OBJECTS:ARDent_debug>)
LIST (APPEND ARDent_sources $<TARGET_OBJECTS:ARDent_logging>)
LIST (APPEND ARDent_sources $<TARGET_OBJECTS:ARDent_seeding>)

# ##################################################################################################
# DO NOT CHANGE PAST THIS POINT
# ##################################################################################################

ADD_LIBRARY (ARDent_provider SHARED ${ARDent_sources})

SET_TARGET_PROPERTIES  (ARDent_provider PROPERTIES OUTPUT_NAME "ardent")
SET_TARGET_PROPERTIES  (ARDent_provider PROPERTIES PREFIX "")
SET_TARGET_PROPERTIES  (ARDent_provider PROPERTIES SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})

TARGET_COMPILE_OPTIONS (ARDent_provider PRIVATE ${ARDent_LIB_CFLAGS})
TARGET_LINK_OPTIONS    (ARDent_provider PRIVATE ${ARDent_LIB_LDFLAGS})

#TARGET_LINK_LIBRARIES  (ARDent_provider PRIVATE ${OPENSSL_LIB})
TARGET_LINK_LIBRARIES  (ARDent_provider PRIVATE ${OPENSSL_LIB_PATH}/libcrypto${CMAKE_SHARED_LIBRARY_SUFFIX})
TARGET_LINK_LIBRARIES  (ARDent_provider PRIVATE "${JITTER_LIB}")

IF (external)
TARGET_LINK_LIBRARIES  (ARDent_provider PRIVATE ${CMAKE_DL_LIBS})
ENDIF (external)

