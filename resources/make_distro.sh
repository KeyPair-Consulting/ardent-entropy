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

BASEVER="1.0.0"

# Temporary directory
TEMPDIR=-${BASEVER}
DISTRO_DIR=./distro/${TEMPDIR}
if [[ -d $DISTRO_DIR ]]; then
	rm -rf $DISTRO_DIR/*
else
	mkdir -p $DISTRO_DIR
fi
cd $DISTRO_DIR

# Directories
ln -sf ../../app
ln -sf ../../include
ln -sf ../../resources
ln -sf ../../source
ln -sf ../../optest
ln -sf ../../example

# Files
ln -sf ../../CHANGES.md
ln -sf ../../CUSTOM-SYSLOG.md
ln -sf ../../README.md
ln -sf ../../SERVICES.md
ln -sf ../../SEED-INFO.md
ln -sf ../../LICENSE
ln -sf ../../.gitignore
ln -sf ../../CMakeLists.txt

# Needed subdir
mkdir build

# Make the tarball
cd ..
tar czhf ARDent-Entropy-Provider-${BASEVER}.tar.gz ${TEMPDIR}
rm -rf ${TEMPDIR}
cd ..

