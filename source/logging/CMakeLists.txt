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
SET  (ARDent_logging_sources ardent_logging.c)
LIST (APPEND ARDent_logging_sources sink_dummy.c)
LIST (APPEND ARDent_logging_sources sink_syslog.c)
LIST (APPEND ARDent_logging_sources sink_stderr.c)
LIST (APPEND ARDent_logging_sources sink_extern.c)

# ##################################################################################################
# STATIC Compilation for linking
# ##################################################################################################

# Rest of libacvpro
ADD_LIBRARY (ARDent_logging OBJECT ${ARDent_logging_sources})

IF (TRACE_SINK)
ADD_DEFINITIONS(-DARDent_TRACE_SINK)
ENDIF ()

TARGET_COMPILE_OPTIONS (ARDent_logging PRIVATE ${ARDent_LIB_CFLAGS} "-fPIC")
IF(CMAKE_VERSION GREATER_EQUAL 3.13.0)
    TARGET_LINK_OPTIONS(ARDent_logging PRIVATE ${ARDent_LIB_LDFLAGS})
ENDIF ()


