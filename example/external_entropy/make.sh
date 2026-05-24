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
   echo "Compile the example external entropy source for the KeyPair Management Provider."
   echo
   echo "Syntax:  $0 [--libdir </path/to/dir>] [--incdir </path/to/dir>] [--debug] [--echo] [--help]"
   echo "Options:"
   echo "--libdir    Set the path for the Jitter Entropy library (libjitterentropy.a); default is the local directory ('.')"
   echo "--incdir    Set the path for the Jitter Entropy include files; default is the local directory ('.')"
   echo "--debug     Include GDB debug symbols (default OFF)"
   echo "--echo      Echo the command but do not execute it (dry run for testing arguments)"    
   echo "--help      Print this message and exit"
   echo
}

# Setup defaults
DEBUG=""
LIBDIR="."
INCDIR="."
ECHO_ME=""
OUTNAME="libextjitter.so"
CFLAGS="-fPIC -g -Wl,--no-undefined -shared -Wl,-soname,"$OUTNAME
COMPILER="gcc"

# Check for compiler set by environment
if [[ ! -z "${CC}" ]]; then
	COMPILER="${CC}"
fi

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
    --incdir) shift
              INCDIR="$1"
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

$ECHO_ME $COMPILER $DEBUG $CFLAGS -I$INCDIR -I../../include external_entropy.c -o $OUTNAME $LIBDIR/libjitterentropy.a


