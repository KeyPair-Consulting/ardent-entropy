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

print_usage()
{
   echo "Compile the example external entropy source for the ARDent Entropy Provider."
   echo
   echo "Syntax:  $0 [--libdir </path/to/dir>] [--incdir </path/to/dir>] [--debug] [--echo] [--help]"
   echo "Options:"
   echo "--libdir    The name of the subdir that OpenSSL isntalls libraries (default: 'lib64')"
   echo "--debug     Include GDB debug symbols (default OFF)"
   echo "--echo      Echo the command but do not execute it (dry run for testing arguments)"    
   echo "--help      Print this message and exit"
   echo
}

# Got OpenSSL root path
if [[ ! -z "${OPENSSL_ROOT}" ]]; then
    OPENSSL_ROOT=${OPENSSL_ROOT}
else
    echo "The environment variable 'OPENSSL_ROOT' must be set to the absolute path to the openssl install directory"
	exit 0
fi

# Setup defaults
DEBUG=""
LIBDIR="lib64"
ECHO_ME=""
OUTNAME="libextlogging.so"
CFLAGS="-fPIC -g -Wl,--no-undefined -shared -Wl,-soname,"$OUTNAME
COMPILER="gcc"

# Process arguments
while test $# -gt 0
do
    case "$1" in
    --help)   print_usage
              exit 0
              ;;
    --echo)   ECHO_ME="echo"
              ;;
    --debug)  DEBUG="-ggdb3"
              ;;
    --libdir) shift
              LIBDIR="$1"
              ;;
    *)        echo "Unknown argument: $1"
              echo
              print_usage
              exit 1
              ;;
    esac
    shift
done

# Check for compiler set by environment
if [[ ! -z "${CC}" ]]; then
	COMPILER="${CC}"
fi

$ECHO_ME $COMPILER $DEBUG $CFLAGS -I$OPENSSL_ROOT/include -I../../include external_logging.c -o $OUTNAME \
    $OPENSSL_ROOT/$LIBDIR/libcrypto.so \
    $OPENSSL_ROOT/$LIBDIR/ossl-modules/ardent.so


