#
# Copyright 2023 Sly Technologies Inc. All Rights Reserved.
#
# 1. Copying, modification, and distribution of this file, or executable
# versions of this file, is governed by the terms of the Sly Technologies Software
# license agreement under which this file was made available. If you do not
# agree to the terms of the license do not install, copy, access or
# otherwise use this file.
#
# 2. Under the Sly Technologies Software license agreement you are granted a
# limited, non-exclusive, non-assignable, copyright license to copy, modify
# and distribute this file in conjunction with Sly Technologies software
# supplied by Sly Technologies A/S.
#
# 3. The full Sly Technologies Software license agreement is included in this
# distribution, please see LICENSE text file
#
# 4. Redistributions of source code must retain this copyright notice,
# list of conditions and the following disclaimer.
#
# THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTIES, EXPRESS OR
# IMPLIED, AND Sly Technologies DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING ANY
# IMPLIED WARRANTY OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, OR OF
# FITNESS FOR A PARTICULAR PURPOSE. TO THE EXTENT NOT PROHIBITED BY
# APPLICABLE LAW, IN NO EVENT SHALL Sly Technologies BE LIABLE FOR PERSONAL INJURY,
# OR ANY INCIDENTAL, SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES WHATSOEVER,
# INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, CORRUPTION OR
# LOSS OF DATA, FAILURE TO TRANSMIT OR RECEIVE ANY DATA OR INFORMATION,
# BUSINESS INTERRUPTION OR ANY OTHER COMMERCIAL DAMAGES OR LOSSES, ARISING
# OUT OF OR RELATED TO YOUR USE OR INABILITY TO USE Sly Technologies SOFTWARE OR
# SERVICES OR ANY THIRD PARTY SOFTWARE OR APPLICATIONS IN CONJUNCTION WITH
# THE Sly Technologies SOFTWARE OR SERVICES, HOWEVER CAUSED, REGARDLESS OF THE THEORY
# OF LIABILITY (CONTRACT, TORT OR OTHERWISE) AND EVEN IF Sly Technologies HAS BEEN
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. SOME JURISDICTIONS DO NOT ALLOW
# THE EXCLUSION OR LIMITATION OF LIABILITY FOR PERSONAL INJURY, OR OF
# INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THIS LIMITATION MAY NOT APPLY TO YOU.
#
#



#
# Makefile for jNetWorks native modules
#

# Default install path
INSTALL_PATH?=/opt/jnetworks

#


# Set default locale for commands like tr, bash and others.
LC_ALL := C

# Use the bash shell for all Makefile shell commands
# bash shell is required because of the use of PIPESTATUS[0] in color-command macro function.
SHELL := /usr/bin/env LC_ALL=C bash

#
# Platform/Architecture
#
PLATFORM := $(shell uname -s | tr "[A-Z]" "[a-z]")
SUBARCH  := $(shell uname -m)
CPUARCH  := $(shell uname -p)

#
# clear flags - use USER_ variables to append to flags
#
#IFLAGS =
#CFLAGS =
#LDFLAGS =

#
#
#

INC_DIR:= $(INSTALL_PATH)/include
LIB_DIR:= $(INSTALL_PATH)/lib

TARGET_DIR:= ../../../../target
TARGET_SHARED_DIR:= $(TARGET_DIR)/lib

#




#
# Put common example definitions here
#

OBJS = $(SRCS:%.c=$(BLD_PREFIX)%.o) $(CXX_SRCS:%.cpp=$(BLD_PREFIX)%.o)
DEPS = $(SRCS:%.c=$(BLD_PREFIX)%.deps) $(CXX_SRCS:%.cpp=$(BLD_PREFIX)%.deps)

# Set the include path
IFLAGS += -I$(INC_DIR)
IFLAGS += -Iinclude

# Require POSIX libraries
LDFLAGS += -L$(LIB_DIR)
LDFLAGS += -lpthread
# Use of argparse requires -lm (ceil function) on Linux, benign on FreeBSD
LDFLAGS += -lm

#
# Default compile flags common to C/C++.
#
# You can add more from command line e.g:
#
# USER_CFLAGS=-m32
# USER_CXXFLAGS=-m32
#

# Check for 32/64bit to enable optimal GCC architecture
ifeq ($(findstring 64,$(SUBARCH)),64)
ifeq ($(CPUARCH), ppc64le)
COMPILEFLAGS += -mcpu=powerpc64
else
COMPILEFLAGS += -march=nocona
endif
else
COMPILEFLAGS += -march=prescott
endif

#


COMPILEFLAGS += -O2
COMPILEFLAGS += -g
COMPILEFLAGS += $(DEFINES)
COMPILEFLAGS += -Wall -Wextra -Wcast-qual -Winline -Wsign-compare -Wunused-parameter -Wpointer-arith -Wshadow

#
# Compile flags that does *not* apply to C++
#
CFLAGS += -Wstrict-prototypes
CFLAGS += -Wmissing-prototypes

#
# Append USER_CFLAGS to the end of CFLAGS in order to be able to overload options
#
# Make sure that an empty definition of USER_CFLAGS does not generate an extra space in command.
#
CFLAGS += $(COMPILEFLAGS) $(IFLAGS) $(EXTRA_CFLAGS) $(USER_CFLAGS)
CXXFLAGS += $(COMPILEFLAGS) $(IFLAGS) $(EXTRA_CXXFLAGS) $(USER_CXXFLAGS)
CPPFLAGS += $(EXTRA_CPPFLAGS) $(USER_CPPFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS) $(USER_LDFLAGS)
LDOBJS += $(EXTRA_LDOBJS) $(USER_LDOBJS)

# Workaround Ubuntu problem - needs libm last
LDFLAGS += -lm
LDFLAGS_SHARED = $(LDFLAGS) -shared -g -static-libstdc++ -static-libgcc

# Use CXX as linker for all targets containing C++ files
ifeq ($(CXX_SRCS),)
  LINKER = $(CC)
else
  LINKER = $(CXX)
endif

#
#
#

.PHONY: all
all: build

.PHONY: build
build:: $(TARGET)


$(TARGET): $(OBJS)
	$(if $(Q),,@echo "  LINKING: $(@) ($(^))")
	$(if $(V),,@)$(LINKER) $(^) $(LDOBJS) $(LDFLAGS) -o $(@)


$(TARGET_SHARED): $(OBJS)
	$(if $(Q),,@echo "  LINKING: $(@) ($(^))")
	$(if $(V),,@)$(LINKER) $(^) $(LDOBJS) $(LDFLAGS_SHARED) -o $(@)

#


#
# Default %.c -> %.o rule
#
$(BLD_PREFIX)%.o: %.c
	$(if $(Q),,@echo "  CC COMPILE: $(<) -> $(@)")
	$(if $(V),,@)$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $(@) $(realpath $(<))

#
# Default %.cpp -> %.o rule
#
$(BLD_PREFIX)%.o: %.cpp
	$(if $(Q),,@echo "  CX COMPILE: $(<) -> $(@)")
	$(if $(V),,@)$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) -o $(@) $(realpath $(<))


#
# clean
#
.PHONY: clean
clean::
	@rm -f $(TARGET)
	@rm -f $(addsuffix .lnk, $(TARGET))
	@rm -f $(addsuffix .buildflags, $(TARGET))
	@rm -f $(OBJS)
	@rm -f $(DEPS)

.PHONY: install
install:: all
#



#


#
# EOF
#
