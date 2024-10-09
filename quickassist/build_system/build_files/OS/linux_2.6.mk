######
#
# Makefile Linux 2.6 Kernel Specific Definitions for the common build system 
#
# @par
#   BSD LICENSE
# 
#   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
# 
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
#  version: QAT20.L.1.1.50-00003
######
######
#path to production header files and to add another "-I<path to another directory of include files>"
INCLUDES+=-I./


ifeq ($($(PROG_ACY)_OS_LEVEL), user_space)
CFLAGS+=-fPIC $(DEBUGFLAGS) -Wall -Wpointer-arith $(INCLUDES)
endif




ifeq ($($(PROG_ACY)_EXTRA_WARNINGS),y)
EXTRA_CFLAGS+= -Wno-div-by-zero -Wfloat-equal -Wtraditional  -Wundef -Wno-endif-labels \
      -Wshadow -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wsign-compare -Waggregate-return \
      -Wstrict-prototypes  -Wmissing-prototypes -Wmissing-declarations  -Wmissing-noreturn \
      -Wmissing-format-attribute -Wno-multichar -Wno-deprecated-declarations -Wpacked -Wpadded -Wredundant-decls -Wnested-externs -Wunreachable-code \
      -Winline -Wlong-long -Wdisabled-optimization 

## unrecognized options
## -Wextra -Wdeclaration-after-statement -Wlarger-than-len -Wold-style-definition -Wmissing-field-initializers -Winvalid-pch
## -Wvariadic-macros -Wno-pointer-sign
endif


LIB_SHARED_FLAGS+=-shared -soname $(LIB_SHARED)
LIB_STATIC_FLAGS=
EXE_FLAGS?=

#The definition of SYSROOT is used for NAC cross-compilation
ifdef SYSROOT
EXTRA_CFLAGS += --sysroot=$(SYSROOT)
LIB_SHARED_FLAGS += --sysroot=$(SYSROOT)
EXE_FLAGS += --sysroot=$(SYSROOT)
endif
