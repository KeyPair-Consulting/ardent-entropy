#!/bin/sh
##########################################################################################
# Copyright (C) 2021-2026 Symbiotic Systems Research, LLC
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
##########################################################################################
# 9/10/2023: Initial Release
# 7/10/2025: Add detection of 'source'
##########################################################################################

# Check whether we are sourced
# https://stackoverflow.com/questions/2683279/how-to-detect-if-a-script-is-being-sourced
sourced=0
if [ -n "$ZSH_VERSION" ]; then 
  case $ZSH_EVAL_CONTEXT in *:file) sourced=1;; esac
elif [ -n "$KSH_VERSION" ]; then
  [ "$(cd -- "$(dirname -- "$0")" && pwd -P)/$(basename -- "$0")" != "$(cd -- "$(dirname -- "${.sh.file}")" && pwd -P)/$(basename -- "${.sh.file}")" ] && sourced=1
elif [ -n "$BASH_VERSION" ]; then
  (return 0 2>/dev/null) && sourced=1 
else # All other shells: examine $0 for known shell binary filenames.
  # Detects `sh` and `dash`; add additional shell filenames as needed.
  case ${0##*/} in sh|-sh|dash|-dash) sourced=1;; esac
fi
if [ $sourced -eq 0 ]; then
    echo "This script must be executed using 'source' to affect the local environment."
	return 1
fi
# Check for required root path
if [ $# -lt 1 ]; then
    echo "This script requires an argument containing the path to the 'root' or 'prefix' folder for the OpenSSL installation to use."
	return 1
fi

# Set environment variables
export OPENSSL_ROOT=$1
export OPENSSL_CONF=$OPENSSL_ROOT/ssl/openssl.cnf
export OPENSSL_MODULES=$OPENSSL_ROOT/lib64/ossl-modules
export LD_LIBRARY_PATH=$OPENSSL_ROOT/lib64:$OPENSSL_MODULES

if [[ -z "${PATH_SAVE}" ]]; then
	export PATH_SAVE=$PATH
fi
export PATH=$OPENSSL_ROOT/bin:$PATH_SAVE

