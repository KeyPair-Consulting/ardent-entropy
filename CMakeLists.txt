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
# CMake Information
# ##################################################################################################

# DEV NOTE: Picked 3.13.0 because of
#  1) RPATH changes
#  2) TARGET_LINK_OPTIONS
CMAKE_MINIMUM_REQUIRED (VERSION 3.13.0)
IF (${CMAKE_VERSION} VERSION_LESS "3.13.0") # Message here in case min-version is lowered for a project
    MESSAGE("WARNING: CMake version is < 3.13 and may fail to build correctly.  Please update.")
ENDIF ()

#SET(CXX_STANDARD 99)
SET(C_STANDARD 99)

# Choose build type
SET(CMAKE_BUILD_TYPE Debug) 
#SET(CMAKE_BUILD_TYPE Release) 

# Get Environment (Host and Target) for later option selection
IF ("${CMAKE_SYSTEM_NAME}" STREQUAL "")  # Is it already set to something?
    MESSAGE("-- Setting Target OS to Host OS; user can specify with '-DCMAKE_SYSTEM_NAME=something'")
    SET(CMAKE_SYSTEM_NAME ${CMAKE_HOST_SYSTEM_NAME})
ENDIF ()
MESSAGE("-- Detected Host OS    : ${CMAKE_HOST_SYSTEM_NAME}")
MESSAGE("-- Detected Target OS  : ${CMAKE_SYSTEM_NAME}")

# Set Standard options for ACVPro applications and libraries
LIST(APPEND _APP_CFLAGS "-Wall" "-Wextra")
LIST(APPEND _LIB_CFLAGS "-Wall" "-Wextra" "-Wno-unused-parameter")
LIST(APPEND _APP_LDFLAGS "")  # ONLY available with CMake >= 3.13
LIST(APPEND _LIB_LDFLAGS "")  # ONLY available with CMake >= 3.13

IF     (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    SET(CMAKE_C_COMPILER "gcc")
ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    MESSAGE(FATAL_ERROR "-- Please edit the CMakeLists.txt file to enable the OSX architecture(s) to build")
    #SET(CMAKE_OSX_ARCHITECTURES $(ARCHS_STANDARD) CACHE INTERNAL "" FORCE)  # Both (req's cmake 3.19)
    #SET(CMAKE_OSX_ARCHITECTURES "arm64" CACHE INTERNAL "" FORCE)
    #SET(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE INTERNAL "" FORCE)
    SET(CMAKE_C_COMPILER "clang")
ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
    SET(CMAKE_C_COMPILER "gcc")
ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    # Reset some flags
    UNSET(_APP_CFLAGS)
    UNSET(_LIB_CFLAGS)
    LIST(APPEND _APP_CFLAGS "-Wall")
    LIST(APPEND _LIB_CFLAGS "-Wall")
    # Windows "-Wall" outputs a *LOT* more; silence them
    ADD_DEFINITIONS("/wd4061")  # Missing case label
    ADD_DEFINITIONS("/wd4100")  # Unused formal parameter
    ADD_DEFINITIONS("/wd4191")  # Unsafe conversion of function type
    ADD_DEFINITIONS("/wd4242")  # Conversion
    ADD_DEFINITIONS("/wd4244")  # Conversion
    ADD_DEFINITIONS("/wd4267")  # Conversion
    ADD_DEFINITIONS("/wd4389")  # Sign/Unsigned mismatch
    ADD_DEFINITIONS("/wd4464")  # Relative path in #include
    ADD_DEFINITIONS("/wd4505")  # Unused local function
    ADD_DEFINITIONS("/wd4668")  # Undefined preprocessor label (replaced with 0)
    ADD_DEFINITIONS("/wd4702")  # Unreachable Code (safety return at end of switch)
    ADD_DEFINITIONS("/wd4706")  # Assignment within conditional
    ADD_DEFINITIONS("/wd4710")  # Function not inlined
    ADD_DEFINITIONS("/wd4711")  # Marked for inline
    ADD_DEFINITIONS("/wd4820")  # Structure packing offsets
    ADD_DEFINITIONS("/wd4996")  # Deprecated/Unsafe function (recommend safe variant)
    ADD_DEFINITIONS("/wd5045")  # Spectre mitigation
ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "AIX")
    # Check 64-bit flag
    SET(AIX64 OFF CACHE BOOL "Specify build for AIX 64-bit (default 32-bit)")
    IF (AIX64)
        IF (NOT DEFINED ENV{OBJECT_MODE} OR NOT "$ENV{OBJECT_MODE}" MATCHES "64")
            MESSAGE(WARNING "Environment variable 'OBJECT_MODE' is missing or invalid.")
            MESSAGE(FATAL_ERROR "Please run 'export OBJECT_MODE=64' to set the variable and try again.")
        ENDIF ()
        MESSAGE("-- Building AIX 64-bit")
        #ADD_COMPILE_OPTIONS("-Wl,-b64 -maix64")
        #ADD_LINK_OPTIONS("-Wl,-b64 -maix64")
        LIST(APPEND _APP_CFLAGS "-Wl,-b64" "-maix64")
        LIST(APPEND _LIB_CFLAGS "-Wl,-b64" "-maix64")
        LIST(APPEND _APP_LDFLAGS "-Wl,-b64" "-maix64")
        LIST(APPEND _LIB_LDFLAGS "-Wl,-b64" "-maix64")
    ELSE()
        MESSAGE("-- Building AIX 32-bit")
    ENDIF ()
    # Set compiler!!
    SET(CMAKE_C_COMPILER "gcc")
ENDIF()

SET(add-cflag "" CACHE STRING "Specify additional arguments for CFLAGS")
IF (add-cflag)
    LIST(APPEND _APP_CFLAGS ${add-cflag})
    LIST(APPEND _LIB_CFLAGS ${add-cflag})
ENDIF ()
SET(add-ldflag "" CACHE STRING "Specify additional arguments for LDFLAGS")
IF (add-ldflag)
    LIST(APPEND _APP_LDFLAGS ${add-ldflag})
    LIST(APPEND _LIB_LDFLAGS ${add-ldflag})
ENDIF ()

# Disallow undefined symbols in shared objects (force symbol resolution at link-time)
SET(CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")

# ##################################################################################################
# Project Information
# ##################################################################################################

PROJECT (KPEP)

# ##################################################
# Verbose output?
SET(verbose OFF CACHE BOOL "Specify that the makefile show the exact command line)")
IF (verbose)
    SET(CMAKE_VERBOSE_MAKEFILE ON)
ELSE()
    SET(CMAKE_VERBOSE_MAKEFILE OFF)
ENDIF (verbose)

# ##################################################
# Should we support use of external libraries (requires runtime linking, may not be available in all environments)
SET(external ON CACHE BOOL "Specify to enable the use of external libraries to extend capabilities; requires runtime linking which may not be available in all environment (default: ON)")
IF (NOT external)
    MESSAGE("-- Support for external libraries is DISABLED")
    LIST(APPEND _LIB_CFLAGS "-D_DISABLE_EXTERNAL")
ENDIF (NOT external)

# ##################################################
# Should we build KPEP 'utility' application?
SET(utility ON CACHE BOOL "Specify to build 'utility' application (default: ON)")
IF (NOT utility)
    MESSAGE("-- Application 'utility' is DISABLED and will not be built")
ENDIF (NOT utility)

# ##################################################
# Should we build KPEP 'rand' application?
SET(rand ON CACHE BOOL "Specify to build 'rand' application (default: ON)")
IF (NOT rand)
    MESSAGE("-- Application 'rand' is DISABLED and will not be built")
ENDIF (NOT rand)

# ##################################################
# Should we build KPEP 'debug' application?
SET(debug ON CACHE BOOL "Specify to build 'debug' application (default: ON)")
IF (NOT debug)
    MESSAGE("-- Application 'debug' is DISABLED and will not be built")
ENDIF (NOT debug)

# ##################################################
# Should we build KPEP test applications?
SET(tests OFF CACHE BOOL  "Specify to build unit test and stress test applications (default: OFF)")
IF (tests)
    MESSAGE("-- Testing applications are ENABLED and will be built")
ENDIF (tests)

# ##################################################
# Jitterentropy dependency
SET(jitter-source "" CACHE PATH "Jitterentropy source checkout containing a prebuilt libjitterentropy.a")
SET(jitter-lib "" CACHE FILEPATH "Path to an external libjitterentropy.a archive")
SET(jitter-include "" CACHE PATH "Flat directory containing the Jitterentropy headers")

IF (jitter-source)
    IF (jitter-lib OR jitter-include)
        MESSAGE(FATAL_ERROR "Specify either -Djitter-source=... or both -Djitter-lib=... and -Djitter-include=..., not both modes.")
    ENDIF ()

    SET(JITTER_SOURCE_DIR "${jitter-source}")
    SET(JITTER_LIB "${JITTER_SOURCE_DIR}/libjitterentropy.a")
    SET(JITTER_INCLUDE_DIRS "${JITTER_SOURCE_DIR}" "${JITTER_SOURCE_DIR}/src")

    IF (NOT EXISTS "${JITTER_LIB}")
        MESSAGE(FATAL_ERROR "Jitterentropy archive not found: '${JITTER_LIB}'. Build libjitterentropy.a in the source checkout or specify -Djitter-lib=... with -Djitter-include=....")
    ENDIF ()
    IF (NOT EXISTS "${JITTER_SOURCE_DIR}/jitterentropy.h" OR
        NOT EXISTS "${JITTER_SOURCE_DIR}/jitterentropy-base-user.h" OR
        NOT EXISTS "${JITTER_SOURCE_DIR}/src/jitterentropy-sha3.h" OR
        NOT EXISTS "${JITTER_SOURCE_DIR}/src/jitterentropy-internal.h")
        MESSAGE(FATAL_ERROR "Required Jitterentropy headers were not found in '${JITTER_SOURCE_DIR}' and '${JITTER_SOURCE_DIR}/src'.")
    ENDIF ()
ELSEIF (jitter-lib OR jitter-include)
    IF (NOT jitter-lib OR NOT jitter-include)
        MESSAGE(FATAL_ERROR "The separate Jitterentropy mode requires both -Djitter-lib=... and -Djitter-include=....")
    ENDIF ()

    SET(JITTER_LIB "${jitter-lib}")
    SET(JITTER_INCLUDE_DIRS "${jitter-include}")

    IF (NOT EXISTS "${JITTER_LIB}")
        MESSAGE(FATAL_ERROR "Jitterentropy archive not found: '${JITTER_LIB}'.")
    ENDIF ()
    IF (NOT IS_DIRECTORY "${jitter-include}")
        MESSAGE(FATAL_ERROR "Jitterentropy include directory not found: '${jitter-include}'.")
    ENDIF ()
    FOREACH (JITTER_HEADER jitterentropy.h jitterentropy-base-user.h jitterentropy-sha3.h jitterentropy-internal.h)
        IF (NOT EXISTS "${jitter-include}/${JITTER_HEADER}")
            MESSAGE(FATAL_ERROR "Jitterentropy header not found: '${jitter-include}/${JITTER_HEADER}'. The separate include directory must contain all required headers in one flat directory.")
        ENDIF ()
    ENDFOREACH ()
ELSE ()
    MESSAGE(FATAL_ERROR "Jitterentropy is required. Specify -Djitter-source=... or both -Djitter-lib=... and -Djitter-include=....")
ENDIF ()

# ##################################################
# Should we build the EXAMPLE external jitter source?
SET(example-external-jitter OFF CACHE BOOL "Specify to build the example external library using the built-in libjitterentropy.a (default: OFF)")
IF (example-external-jitter)
    MESSAGE("-- Detected 'example-external-jitter' flag; Building example external entropy source")
ENDIF (example-external-jitter)

# ##################################################
# Should we build the EXAMPLE external logging sink?
SET(example-external-logging OFF CACHE BOOL "Specify to build the example external library using the built-in 'stderr' logging sink (default: OFF)")
IF (example-external-logging)
    MESSAGE("-- Detected 'example-external-logging' flag; Building example external logging sink")
ENDIF (example-external-logging)

# ##################################################
# External exclusion check
IF ((NOT external) AND (example-external-jitter OR example-external-logging))
    MESSAGE(FATAL_ERROR "-- Invalid configuration: support for external libraries is disabled, but example external components are enabled.")
ENDIF ()

# ##################################################
# Debugging options
SET(DEBUG_DRBG OFF CACHE BOOL "Add code to output additional debug data (default: OFF)")
SET(DEBUG_CAST OFF CACHE BOOL "Enable additional output for debugging the 'Cryptographic Algorithm Self Tests (CASTs)' (default: OFF)")
SET(DEBUG_INTEGRITY OFF CACHE BOOL "Enable additional output for debugging the startup Integrity Test (default: OFF)")

IF (DEBUG_DRBG)
    ADD_DEFINITIONS(-DDEBUG_DRBG)
    MESSAGE("-- Detected 'DEBUG_DRBG' flag; Building support for add'l support of DRBG execution")
ENDIF ()
IF (DEBUG_CAST)
    ADD_DEFINITIONS(-DDEBUG_CAST)
    MESSAGE("-- Detected 'DEBUG_CAST' flag; Building support for add'l output of CAST execution")
ENDIF ()
IF (DEBUG_INTEGRITY)
    ADD_DEFINITIONS(-DDEBUG_INTEGRITY)
    MESSAGE("-- Detected 'DEBUG_DRBG' flag; Building support for add'l output of the integrity test")
ENDIF ()

# ##################################################
# FIPS Operational Testing
SET(FIPS_OPTEST OFF CACHE BOOL "Add code to trigger errors for FIPS Operational Testing demonstration (default: OFF)")

IF (FIPS_OPTEST)
    ADD_DEFINITIONS(-DFIPS_OPTEST)
    MESSAGE("-- Detected 'FIPS_OPTEST' flag; Building support for FIPS Operational Testing")
ENDIF ()

# ##################################################
# FIPS Operational Testing
SET(FIPS_ACVP OFF CACHE BOOL "Add code to facilitate ACVP testing (default: OFF)")

IF (FIPS_ACVP)
    ADD_DEFINITIONS(-DFIPS_ACVP)
    MESSAGE("-- Detected 'FIPS_ACVP' flag; Building support for FIPS ACVP Testing")
ENDIF ()

# ##################################################################################################
# RPATH Configuration
# ##################################################################################################

# DO MORE RESEARCH:
# -Wl,-rpath=/usr/local/ssl/lib -Wl,--enable-new-dtags

# Don't skip, err -- use the full RPATH for the build tree
###set(CMAKE_SKIP_BUILD_RPATH FALSE)
 
# when building, don't use the install RPATH already
# (but later on when installing)
###SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
###set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
###SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

# Ensure RPATH works on MacOSX
###SET(CMAKE_MACOSX_RPATH 1)

# Set the RPATH on specific targets
#SET_TARGET_PROPERTIES(ACVPro PROPERTIES INSTALL_RPATH "@loader_path")
#if (shim)
#    SET_TARGET_PROPERTIES(${shim_name} PROPERTIES INSTALL_RPATH "@loader_path")
#endif (shim)

# ##################################################################################################
# OpenSSL directories
# ##################################################################################################

# Verify we have the absolute path to the KPFP Openssl Installation
IF (NOT DEFINED ENV{OPENSSL_ROOT}) # This should *not* be $ENV(...)
    MESSAGE(FATAL_ERROR "-- Missing environment variable: '$OPENSSL_ROOT' holding the absolute path to the KPFP installation ('--prefix') directory.")
ENDIF ()
SET(OPENSSL_ROOT $ENV{OPENSSL_ROOT})
MESSAGE("-- Detected OpenSSL/KPFP root path: '${OPENSSL_ROOT}'")

# Set OpenSSL library directory (check environment)
IF (DEFINED ENV{OPENSSL_LIBDIR}) # This should *not* be $ENV(...)
    SET(OPENSSL_LIB_PATH $ENV{OPENSSL_MODULES})
ELSE ()
    # Set the OpenSSL library path from the OPENSSL_ROOT; based on OS/Architecture
    IF     (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        SET(OPENSSL_LIB_PATH ${OPENSSL_ROOT}/lib64)
    ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        SET(OPENSSL_LIB_PATH ${OPENSSL_ROOT}/lib)
    ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
        SET(OPENSSL_LIB_PATH ${OPENSSL_ROOT}/lib)
    ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
        SET(OPENSSL_LIB_PATH ${OPENSSL_ROOT}/lib/64)
    ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        SET(OPENSSL_LIB_PATH ${OPENSSL_ROOT}/lib)
    ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "AIX")
        # Check 64-bit flag
        IF (aix64)
            SET(OPENSSL_LIB_PATH ${OPENSSL_ROOT}/usr/lib)
        ELSE ()
            SET(OPENSSL_LIB_PATH ${OPENSSL_ROOT}/usr/lib)
        ENDIF ()
    ENDIF()
ENDIF ()

# Set OpenSSL configuration directory
IF (DEFINED ENV{OPENSSL_SSLDIR}) # This should *not* be $ENV(...)
    SET(OPENSSL_SSL_PATH $ENV{OPENSSL_SSLDIR})
ELSE ()
    SET(OPENSSL_SSL_PATH ${OPENSSL_ROOT}/ssl)
ENDIF ()

# Set OpenSSL modules directory
IF (DEFINED ENV{OPENSSL_MODULES}) # This should *not* be $ENV(...)
    SET(OPENSSL_MODULE_PATH $ENV{OPENSSL_MODULES})
ELSE ()
    SET(OPENSSL_MODULE_PATH ${OPENSSL_LIB_PATH}/ossl-modules)
ENDIF ()

# This is a list of the shared objects that should be linked against
IF (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    SET(OPENSSL_LIB ${OPENSSL_LIB_PATH}/libcrypto.dll)
ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "AIX")
    SET(OPENSSL_LIB ${OPENSSL_LIB_PATH}/libcrypto.so.3)
ELSE ()
    SET(OPENSSL_LIB ${OPENSSL_LIB_PATH}/libcrypto${CMAKE_SHARED_LIBRARY_SUFFIX})
ENDIF ()

# ##################################################################################################
# Include Paths
# ##################################################################################################

INCLUDE_DIRECTORIES(${KPEP_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${KPEP_SOURCE_DIR}/include/openssl)
INCLUDE_DIRECTORIES(${OPENSSL_ROOT}/include)
INCLUDE_DIRECTORIES(${JITTER_INCLUDE_DIRS})

# ##################################################################################################
# Source  Paths
# ##################################################################################################

# CMakeLists files in this project can refer to :
#   * the root source directory of the project as ${_SOURCE_DIR} and
#   * the root binary directory of the project as ${_BINARY_DIR}.

# Subdirectories containing core  source files
ADD_SUBDIRECTORY ("source")
ADD_SUBDIRECTORY ("source/crypto")
ADD_SUBDIRECTORY ("source/thread")
ADD_SUBDIRECTORY ("source/seeding")
ADD_SUBDIRECTORY ("source/logging")
ADD_SUBDIRECTORY ("source/debug")

# Subdirectories containing  support applications
ADD_SUBDIRECTORY ("app")
ADD_SUBDIRECTORY ("example")

# OpTest Tools?
#IF (FIPS_OPTEST)
#    ADD_SUBDIRECTORY ("optest")
#ENDIF (FIPS_OPTEST)

# Test Applications?
IF (tests)
    ADD_SUBDIRECTORY ("test")
ENDIF (tests)

# ##################################################################################################
# Install Information
# ##################################################################################################

#  Provider
INSTALL(TARGETS KPEP_provider DESTINATION ${OPENSSL_MODULE_PATH}/
    PERMISSIONS 
        OWNER_READ OWNER_EXECUTE OWNER_WRITE
        GROUP_READ GROUP_EXECUTE 
        WORLD_READ WORLD_EXECUTE)
INSTALL(FILES ${KPEP_SOURCE_DIR}/resources/kpepmodule.cnf DESTINATION ${OPENSSL_SSL_PATH}/
    PERMISSIONS 
        OWNER_READ OWNER_WRITE
        GROUP_READ 
        WORLD_READ)
INSTALL(FILES ${KPEP_SOURCE_DIR}/resources/personalization.cnf DESTINATION ${OPENSSL_SSL_PATH}/
    PERMISSIONS 
        OWNER_READ OWNER_WRITE
        GROUP_READ 
        WORLD_READ)
INSTALL(DIRECTORY include/kpep/ DESTINATION ${OPENSSL_ROOT}/include/kpep)
    
#  Utility
IF (utility)
    INSTALL(TARGETS APP_utility DESTINATION ${OPENSSL_ROOT}/bin
        PERMISSIONS 
            OWNER_READ OWNER_EXECUTE OWNER_WRITE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE)
ENDIF (utility)

#  Rand
IF (rand)
    INSTALL(TARGETS APP_rand DESTINATION ${OPENSSL_ROOT}/bin
        PERMISSIONS 
            OWNER_READ OWNER_EXECUTE OWNER_WRITE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE)
ENDIF (rand)

#  Debug
IF (debug)
    INSTALL(TARGETS APP_debug DESTINATION ${OPENSSL_ROOT}/bin
        PERMISSIONS 
            OWNER_READ OWNER_EXECUTE OWNER_WRITE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE)
ENDIF (debug)

# KPEP Test Applications
IF (tests)
    INSTALL(TARGETS APP_rand_stress DESTINATION ${OPENSSL_ROOT}/test
        PERMISSIONS 
            OWNER_READ OWNER_EXECUTE OWNER_WRITE
            GROUP_READ GROUP_EXECUTE 
            WORLD_READ WORLD_EXECUTE)
    INSTALL(TARGETS APP_test_ringbuffer DESTINATION ${OPENSSL_ROOT}/test
        PERMISSIONS 
            OWNER_READ OWNER_EXECUTE OWNER_WRITE
            GROUP_READ GROUP_EXECUTE 
            WORLD_READ WORLD_EXECUTE)
    INSTALL(TARGETS APP_test_runtime_config DESTINATION ${OPENSSL_ROOT}/test
        PERMISSIONS 
            OWNER_READ OWNER_EXECUTE OWNER_WRITE
            GROUP_READ GROUP_EXECUTE 
            WORLD_READ WORLD_EXECUTE)       
ENDIF (tests)

# Example external entropy source using libjitterentropy.a
IF (example-external-jitter)
    INSTALL(TARGETS EXAMPLE_external_jitter DESTINATION ${OPENSSL_MODULE_PATH}/
        PERMISSIONS 
            OWNER_READ OWNER_EXECUTE OWNER_WRITE
            GROUP_READ GROUP_EXECUTE 
            WORLD_READ WORLD_EXECUTE)
ENDIF (example-external-jitter)

# Example external logging sink using stderr
IF (example-external-logging)
    INSTALL(TARGETS EXAMPLE_external_logging DESTINATION ${OPENSSL_MODULE_PATH}/
        PERMISSIONS 
            OWNER_READ OWNER_EXECUTE OWNER_WRITE
            GROUP_READ GROUP_EXECUTE 
            WORLD_READ WORLD_EXECUTE)
ENDIF (example-external-logging)

# FIPS Operational Testing tools
#IF (FIPS_OPTEST)
#    INSTALL(TARGETS TOOL_optest DESTINATION ${OPENSSL_ROOT}/bin
#        PERMISSIONS 
#            OWNER_READ OWNER_EXECUTE OWNER_WRITE
#            GROUP_READ GROUP_EXECUTE
#            WORLD_READ WORLD_EXECUTE)
#    INSTALL(TARGETS TOOL_edkex DESTINATION ${OPENSSL_ROOT}/bin
#        PERMISSIONS 
#            OWNER_READ OWNER_EXECUTE OWNER_WRITE
#            GROUP_READ GROUP_EXECUTE
#            WORLD_READ WORLD_EXECUTE)
#ENDIF (FIPS_OPTEST)

# Fully custom finalization script; must be run after CMake installs above (to the bin/ directory)
INSTALL(CODE "execute_process(COMMAND ${KPEP_SOURCE_DIR}/resources/cmake_finalize_kpep.sh)")

