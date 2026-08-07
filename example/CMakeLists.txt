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
# EXAMPLES
# ##################################################################################################

if (example-external-jitter)
    # Set project source files
    SET  (EXAMPLE_external_jitter_sources external_entropy/external_entropy.c)

    ADD_LIBRARY            (EXAMPLE_external_jitter SHARED ${EXAMPLE_external_jitter_sources})
    SET_TARGET_PROPERTIES  (EXAMPLE_external_jitter PROPERTIES OUTPUT_NAME "extjitter")
    SET_TARGET_PROPERTIES  (EXAMPLE_external_jitter PROPERTIES SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
    TARGET_COMPILE_OPTIONS (EXAMPLE_external_jitter PRIVATE ${KPEP_LIB_CFLAGS})
    TARGET_LINK_OPTIONS    (EXAMPLE_external_jitter PRIVATE ${KPEP_LIB_LDLAGS})
    
    # Substitute your own 'libjitterentropy.a' static library here!
    ADD_LIBRARY            (libjitterentropy STATIC IMPORTED)
    SET_TARGET_PROPERTIES  (libjitterentropy PROPERTIES IMPORTED_LOCATION ${KPEP_SOURCE_DIR}/example/external_entropy/libjitterentropy.a)
    SET_TARGET_PROPERTIES  (libjitterentropy PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${KPEP_SOURCE_DIR}/example/external_entropy)

    # Add libjitterentropy and access to kpep.so for library functions
    TARGET_LINK_LIBRARIES  (EXAMPLE_external_jitter PRIVATE libjitterentropy)
    TARGET_LINK_LIBRARIES  (EXAMPLE_external_jitter PRIVATE KPEP_provider)
endif (example-external-jitter)

if (example-external-logging)
    # Set project source files
    SET  (EXAMPLE_external_logging_sources external_logging/external_logging.c)

    ADD_LIBRARY            (EXAMPLE_external_logging SHARED ${EXAMPLE_external_logging_sources})
    SET_TARGET_PROPERTIES  (EXAMPLE_external_logging PROPERTIES OUTPUT_NAME "extlogging")
    SET_TARGET_PROPERTIES  (EXAMPLE_external_logging PROPERTIES SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
    TARGET_COMPILE_OPTIONS (EXAMPLE_external_logging PRIVATE ${KPEP_LIB_CFLAGS})
    TARGET_LINK_OPTIONS    (EXAMPLE_external_logging PRIVATE ${KPEP_LIB_LDLAGS})

    # Link OpenSSL for access to 'kpfpmoidule.cnf' configuration file 
    TARGET_LINK_LIBRARIES  (EXAMPLE_external_logging PRIVATE ${OPENSSL_LIB})

    # Link to kpep.so for access to a function to translate log-level strings to an enum
    TARGET_LINK_LIBRARIES  (EXAMPLE_external_logging PRIVATE KPEP_provider)

    # Optionally, add an external static library
    #TARGET_LINK_LIBRARIES  (EXAMPLE_external_logging PRIVATE libcustomlog)
    #ADD_LIBRARY            (libcustomlog STATIC IMPORTED)
    #SET_TARGET_PROPERTIES  (libcustomlog PROPERTIES IMPORTED_LOCATION ${KPEP_SOURCE_DIR}/customlog/mylibrary.a)
    #SET_TARGET_PROPERTIES  (libcustomlog PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${KPEP_SOURCE_DIR}/customlog/include)
endif (example-external-logging)

