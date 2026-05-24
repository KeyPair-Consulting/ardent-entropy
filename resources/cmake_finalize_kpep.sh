#!/bin/bash
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
# 05/01/2025: Initial Release
##########################################################################################

##########################################################################################
# When run from CMake, we must back up one directory
cd ..

##########################################################################################
##########################################################################################

print_usage()
{
   echo "Install the KeyPair Management Provider () and complete installation for KeyPair FIPS Provider (KPFP)"
   echo
   echo "Syntax:  kpep_install.sh [--root </path/to/dir>] [--modules </path/to/dir>]"
   echo "                         [--libdir </path/to/dir>] [--ssldir </path/to/dir>]"
   echo "                         [--verbose | -v] [--quiet | -q] [--info] [--cast] [--help]" 
   echo
   echo "--root          Set the directory name for the OSSL3 library directory (no default)."
   echo "                This value can be set using the 'OPENSSL_ROOT' environment variable"
   echo "--libdir        Set the directory name for the OSSL3 library directory (default 'OPENSSL_ROOT/lib64')."
   echo "                This value can be set using the 'OPENSSL_LIBDIR' environment variable"
   echo "--ssldir        Set the directory name for the OSSL3 'ssldirs' directory (default 'OPENSSL_ROOT/ssl')."
   echo "                This value can be set using the 'OPENSSL_SSLDIR' environment variable"
   echo "--modules       Set the directory name for the OSSL3 'modules' directory (default 'OPENSSL_ROOT/lib64/ossl-modules')."
   echo "                This value can be set using the 'OPENSSL_MODULES' environment variable"
   echo
   echo "Options:"
   echo "--verbose, -v   Display additional output for debugging"
   echo "--quiet, -q     Suppress all output"
   echo "--info          After installation, display the configuration information for each provider."
   echo "--cast          After installation, perform the Cryptographic Algorithm Self-Tests (CASTs) on each provider."
   echo "--help          Print this message and exit"
   echo
}

##########################################################################################

# Get default values from environment
if [[ ! -z "${OPENSSL_ROOT}" ]]; then
	OSSL_ROOT="${OPENSSL_ROOT}"
else
    OSSL_ROOT=""
fi
if [[ ! -z "${OPENSSL_LIBDIR}" ]]; then
	OSSL_LIBDIR="${OPENSSL_LIBDIR}"
else
    OSSL_LIBDIR=""
fi
if [[ ! -z "${OPENSSL_SSLDIRS}" ]]; then
	OSSL_SSLDIR="${OPENSSL_SSLDIRS}"
else
    OSSL_SSLDIR=""
fi
if [[ ! -z "${OPENSSL_MODULES}" ]]; then
	OSSL_MODULES="${OPENSSL_MODULES}"
else
    OSSL_MODULES=""
fi

# Action/Operation flags
QUIET=0
VERBOSE=0
RUN_CAST=0
SHOW_INFO=0

# Process CLI arguments
while test $# -gt 0
do
    case "$1" in
    --help)   print_usage
              exit 0
              ;;
    --root)   shift
              OSSL_ROOT="$1"
              ;;
    --libdir) shift
              OSSL_LIBDIR="$1"
              ;;
    --ssldir) shift
              OSSL_SSLDIR="$1"
              ;;
    --modules) shift
              OSSL_MODULES="$1"
              ;;
    --cast)   RUN_CAST=1
              ;;
    --info)   SHOW_INFO=1
              ;;
    --quiet | -q)  
              QUIET=1
              ;;
    --verbose | -v) 
              VERBOSE=1
              ;;
    *)        echo "Unknown argument: $1"
              echo
              print_usage
              exit 1
              ;;
    esac
    shift
done

if [[ ! $OSSL_ROOT ]]; then 
    echo "This script requires the path to the 'root' or 'prefix' folder for the OpenSSL installation to use. The"
    echo "variable can be provided by setting an environment variable 'OPENSSL_ROOT', or using the '--root' argument."
	exit 1
fi
if [[ ! $OSSL_LIBDIR ]]; then 
    OSSL_LIBDIR="$OSSL_ROOT/lib64"
fi
if [[ ! $OSSL_SSLDIR ]]; then 
    OSSL_SSLDIR="$OSSL_ROOT/ssl"
fi
if [[ ! $OSSL_MODULES ]]; then
    OSSL_MODULES="$OSSL_LIBDIR/ossl-modules"
fi

if [ $VERBOSE -eq 1 ]; then
    echo
    echo "Installing to:"
    echo "ROOT    = $OSSL_ROOT"
    echo "LIBDIR  = $OSSL_LIBDIR"
    echo "SSLDIR  = $OSSL_SSLDIR"
    echo "MODULES = $OSSL_MODULES"
    echo "PWD = $PWD"
fi

##########################################################################################

### Generate HMAC for KPEP
(LD_LIBRARY_PATH=$OSSL_LIBDIR:$OSSL_MODULES \
    $OSSL_ROOT/bin/keypair_utility --hmac $OSSL_MODULES/kpep.so)
# Fix the .include for the MAC
sed -i 's@.*include.*kpep.so.mac@.include '$OSSL_MODULES'/kpep.so.mac@g' $OSSL_SSLDIR/kpepmodule.cnf
# Fix the .include for the personalization file
sed -i 's@.*include.*personalization.cnf@.include '$OSSL_SSLDIR'/personalization.cnf@g' $OSSL_SSLDIR/kpepmodule.cnf

### Update paths in the main openssl.cnf file
#sed -i 's@.*include.*kpepmodule.cnf@.include '$OSSL_SSLDIR'/kpepmodule.cnf@g' $OSSL_SSLDIR/openssl.cnf
#sed -i 's@.*include.*kpfpmodule.cnf@.include '$OSSL_SSLDIR'/kpfpmodule.cnf@g' $OSSL_SSLDIR/openssl.cnf

# All required steps complete
if [ $QUIET == 0 ]; then
    echo "-- KPEP custom installation complete!"
fi

# Run the self-tests
if [ $RUN_CAST == 1 ]; then
    echo
    echo " Self-Tests:"
    (LD_LIBRARY_PATH=$OSSL_LIBDIR:$OSSL_MODULES $OSSL_ROOT/bin/keypair_utility --cast kpep)
fi

# Show module info
if [ $SHOW_INFO == 1 ]; then
    echo
    echo " Provider Info:"
    (LD_LIBRARY_PATH=$OSSL_LIBDIR:$OSSL_MODULES $OSSL_ROOT/bin/keypair_utility --info kpep)
fi


