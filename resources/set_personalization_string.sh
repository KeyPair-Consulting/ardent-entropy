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
# 2/6/2026: Initial Release
##########################################################################################

print_usage()
{
   echo "Set the personalization string for this machine."
   echo
   echo "Syntax:  set_personalization_string.sh [--root </path/to/dir>]"
   echo "                                       [--ssldir </path/to/dir>]"
   echo "                                       [--out </path/to/file>]"
   echo "                                       [--string <string-literal>]"
   echo "                                       [--help]" 
   echo
   echo "--root          Set the directory name for the OSSL3 library directory (no default)."
   echo "--ssldir        Set the directory name for the OpenSSL SSL directory (no default)."
   echo "--out           Set the file name to write the personalization string. This defaults"
   echo "                to 'personalization.cnf' in the \$OPENSSL_SSLDIR directory."
   echo "--string        Set the personalization string to the string literal specified in the"
   echo "                second argument.  Use quotes to preserve spaces.  If no value is"
   echo "                specified, it will default to a string consisting of a concatenation"
   echo "                the MAC addresses of the machine."
   echo "--help          Print this message and exit."
   echo
}

##########################################################################################

OSSL_ROOT=""
OSSL_SSLDIR=""
OUTFILE=""
PERSO_STRING=""

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
    --ssldir) shift
              OSSL_SSLDIR="$1"
              ;;
    --out)    shift
              OUTFILE="$1"
              ;;
    --string) shift
              PERSO_STRING="$1"
              ;;
    *)        echo "Unknown argument: $1"
              print_usage
              exit 1
              ;;
    esac
    shift
done

# Set the default string (if none provided)
if [[ ! $PERSO_STRING ]]; then 
    # Get all the MAC addresses as an array
    PERSO_STRING=`cat /sys/class/net/*/address`
    # Truncate to just the first MAC (no spaces)
    PERSO_STRING=`head -c 18 <<< $PERSO_STRING`
fi

# Set the output filename (if none provided)
if [[ ! $OUTFILE ]]; then
    if [[ $OSSL_SSLDIR ]]; then
        OUTFILE="$OSSL_SSLDIR/personalization.cnf"
    elif [[ $OSSL_ROOT ]]; then
        OUTFILE="$OSSL_ROOT/ssl/personalization.cnf"
    else
        echo "Setting the default file requires --ssldir or --root"
        exit 1
    fi
fi

# Set the personalization string
sed -i 's@.*perso.*@perso = '$PERSO_STRING'@g' $OUTFILE

