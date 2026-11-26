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
if [ $sourced -eq 1 ]; then
    echo "This script must be executed without using 'source'"
	exit 1
fi

##########################################################################################
##########################################################################################

print_usage()
{
   echo "Install ARDent files and complete the installation process"
   echo
   echo "Syntax: ardent_install.sh [--root </path/to/dir>] [--libdir </path/to/dir>]"
   echo "                         [--bindir </path/to/dir>] [--ssldir </path/to/dir>]"
   echo "                         [--modules </path/to/dir>] [--verbose | -v] [--quiet | -q]"
   echo "                         [--info] [--cast] [--help]"
   echo
   echo "--root          OpenSSL installation prefix. Used to derive unspecified directories."
   echo "--libdir        OpenSSL library directory."
   echo "--bindir        OpenSSL binary directory."
   echo "--ssldir        OpenSSL SSL/configuration directory."
   echo "--modules       OpenSSL provider module directory."
}

OSSL_ROOT=""
OSSL_LIBDIR=""
OSSL_BINDIR=""
OSSL_SSLDIR=""
OSSL_MODULES=""

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
    --bindir) shift
              OSSL_BINDIR="$1"
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

if [[ $OSSL_ROOT && ! $OSSL_LIBDIR ]]; then OSSL_LIBDIR="$OSSL_ROOT/lib64"; fi
if [[ $OSSL_ROOT && ! $OSSL_BINDIR ]]; then OSSL_BINDIR="$OSSL_ROOT/bin"; fi
if [[ $OSSL_ROOT && ! $OSSL_SSLDIR ]]; then OSSL_SSLDIR="$OSSL_ROOT/ssl"; fi
if [[ $OSSL_LIBDIR && ! $OSSL_MODULES ]]; then OSSL_MODULES="$OSSL_LIBDIR/ossl-modules"; fi

if [[ ! $OSSL_LIBDIR ]]; then echo "Missing OpenSSL library directory: specify --libdir or --root"; exit 1; fi
if [[ ! $OSSL_BINDIR ]]; then echo "Missing OpenSSL binary directory: specify --bindir or --root"; exit 1; fi
if [[ ! $OSSL_SSLDIR ]]; then echo "Missing OpenSSL SSL directory: specify --ssldir or --root"; exit 1; fi
if [[ ! $OSSL_MODULES ]]; then echo "Missing OpenSSL module directory: specify --modules, --libdir, or --root"; exit 1; fi

if [ $VERBOSE -eq 1 ]; then
    echo
    echo "Installing to:"
    echo "ROOT    = $OSSL_ROOT"
    echo "LIBDIR  = $OSSL_LIBDIR"
    echo "SSLDIR  = $OSSL_SSLDIR"
    echo "MODULES = $OSSL_MODULES"
fi

##########################################################################################

### Copy  artifacts
cp bin/ardent.so $OSSL_MODULES/
cp resources/ardentmodule.cnf $OSSL_SSLDIR/

### Copy  utilities
cp bin/ardent_utility $OSSL_BINDIR/
cp bin/ardent_filecheck $OSSL_BINDIR/
cp bin/ardent_rand $OSSL_BINDIR/

### Generate HMAC for ARDent
(LD_LIBRARY_PATH=$OSSL_LIBDIR:$OSSL_MODULES \
    $OSSL_BINDIR/ardent_utility --module --out $OSSL_MODULES/ardent.so.mac --hmac $OSSL_MODULES/ardent.so)
# Fix the .include for the MAC
sed -i 's@.*include.*ardent.so.mac@.include '$OSSL_MODULES'/ardent.so.mac@g' $OSSL_SSLDIR/ardentmodule.cnf
# Fix the .include for the personalization file
sed -i 's@.*include.*personalization.cnf@.include '$OSSL_SSLDIR'/personalization.cnf@g' $OSSL_SSLDIR/ardentmodule.cnf

### Update paths in the main openssl.cnf file
sed -i 's@.*include.*ardentmodule.cnf@.include '$OSSL_SSLDIR'/ardentmodule.cnf@g' $OSSL_SSLDIR/openssl.cnf

# All required steps complete
if [ $QUIET == 0 ]; then
    echo "Installation complete!"
fi

# Run the self-tests
if [ $RUN_CAST == 1 ]; then
    echo
    echo " Self-Tests:"
    (LD_LIBRARY_PATH=$OSSL_LIBDIR:$OSSL_MODULES $OSSL_BINDIR/ardent_utility --cast ardent)
fi

# Show module info
if [ $SHOW_INFO == 1 ]; then
    echo
    echo " Provider Info:"
    (LD_LIBRARY_PATH=$OSSL_LIBDIR:$OSSL_MODULES $OSSL_BINDIR/ardent_utility --info ardent)
fi


