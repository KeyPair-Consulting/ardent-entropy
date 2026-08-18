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
SET  (KPEP_sources kpep_provider.c kpep_self_test.c)

# Core functionality
LIST (APPEND KPEP_sources kpep_internal.c kpep_integrity.c kpep_error.c)
LIST (APPEND KPEP_sources kpep_seeding.c kpep_cpuinfo.c kpep_bio.c)

# Subsystems added by 'objects' instead of static libraries
LIST (APPEND KPEP_sources $<TARGET_OBJECTS:KPEP_crypto>)
LIST (APPEND KPEP_sources $<TARGET_OBJECTS:KPEP_thread>)
LIST (APPEND KPEP_sources $<TARGET_OBJECTS:KPEP_jitter>)
LIST (APPEND KPEP_sources $<TARGET_OBJECTS:KPEP_logging>)
LIST (APPEND KPEP_sources $<TARGET_OBJECTS:KPEP_seeding>)

# ##################################################################################################
# DO NOT CHANGE PAST THIS POINT
# ##################################################################################################

ADD_LIBRARY (KPEP_provider SHARED ${KPEP_sources})

SET_TARGET_PROPERTIES  (KPEP_provider PROPERTIES OUTPUT_NAME "kpep")
SET_TARGET_PROPERTIES  (KPEP_provider PROPERTIES PREFIX "")
SET_TARGET_PROPERTIES  (KPEP_provider PROPERTIES SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})

TARGET_COMPILE_OPTIONS (KPEP_provider PRIVATE ${KPEP_LIB_CFLAGS})
TARGET_LINK_OPTIONS    (KPEP_provider PRIVATE ${KPEP_LIB_LDFLAGS})

#TARGET_LINK_LIBRARIES  (KPEP_provider PRIVATE ${OPENSSL_LIB})
TARGET_LINK_LIBRARIES  (KPEP_provider PRIVATE ${OPENSSL_LIB_PATH}/libcrypto${CMAKE_SHARED_LIBRARY_SUFFIX})

IF (external)
TARGET_LINK_LIBRARIES  (KPEP_provider PRIVATE ${CMAKE_DL_LIBS})
ENDIF (external)

