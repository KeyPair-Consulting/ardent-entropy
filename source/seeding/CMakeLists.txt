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
# Source flies for library
# ##################################################################################################

# Set project source files
SET  (KPEP_seeding_sources seed_control.c async_seed.c ringbuffer.c)
LIST (APPEND KPEP_seeding_sources seed_stub_jitter.c)
LIST (APPEND KPEP_seeding_sources seed_stub_rdseed.c seed_stub_rdrand.c rdcpu_toolbox.c)
LIST (APPEND KPEP_seeding_sources seed_stub_osrand.c)
LIST (APPEND KPEP_seeding_sources seed_stub_extern.c)

# ##################################################################################################
# STATIC Compilation for linking
# ##################################################################################################

ADD_LIBRARY (KPEP_seeding OBJECT ${KPEP_seeding_sources})
TARGET_COMPILE_OPTIONS (KPEP_seeding PRIVATE ${KPEP_LIB_CFLAGS} "-fPIC")
IF(CMAKE_VERSION GREATER_EQUAL 3.13.0)
    TARGET_LINK_OPTIONS(KPEP_seeding PRIVATE ${KPEP_LIB_LDFLAGS})
ENDIF ()


