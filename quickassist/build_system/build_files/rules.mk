####################
#  RULES
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
####################


######Support $(PROG_ACY)_ and previous vars#################################
PROG_ACY?=ICP
ifdef $(PROG_ACY)_KERNEL_SOURCE_ROOT
KERNEL_SOURCE_ROOT=$($(PROG_ACY)_KERNEL_SOURCE_ROOT)
endif
####################################################################


# Build and Install Everything, this is the default rule.
all: install 

#Top-level var for turning on debug#
ifeq ($($(PROG_ACY)_DEBUG),y)
EXTRA_CFLAGS+=-D$(PROG_ACY)_DEBUG
endif

# create .o's from the list of source files
# and keep only the name of the files
OBJECTS=$(notdir $(foreach file,$(SOURCES),$(file:.c=.o)))
OBJ=$(foreach file,$(SOURCES),$(file:.c=.o))
OBJ+=$(foreach file,$(MODULE_SOURCES),$(file:.c=.o))

LIB_SHARED=$(OUTPUT_NAME)_s.so
EXECUTABLE=$(OUTPUT_NAME)

LIB_STATIC=$(OUTPUT_NAME).a
MODULENAME=$(OUTPUT_NAME).o

obj: dirs $(OBJECTS)
$(OBJECTS): | dirs
lib_shared: $(LIB_SHARED)
exe: $(EXECUTABLE)
lib_static: $(LIB_STATIC)
module: $(MODULENAME)

vpath %.o  $($(PROG_ACY)_FINAL_OUTPUT_DIR)
vpath %.c $(dir $(SOURCES))

.PHONY: clean all help

# Cleanup
clean: 
	@echo 'Removing derived objects...'; \
	$(RM) -rf $(OBJECTS) $(LIB_STATIC) $(LIB_SHARED) $(EXECUTABLE) *.o *.cov *.a *.so* *.mod.* *.ko .*.cmd Module.symvers modules.order; \
	$(RM) -rf .tmp_versions; \
	$(RM) -rf $($(PROG_ACY)_FINAL_OUTPUT_DIR);



# rules to create the output directories
dirs:
	@echo 'Creating output directory' ;\
	test -d $($(PROG_ACY)_FINAL_OUTPUT_DIR) || mkdir -p $($(PROG_ACY)_FINAL_OUTPUT_DIR);



#include specific rules according to $(PROG_ACY)_OS and $(PROG_ACY)_OS_LEVEL
include $($(PROG_ACY)_BUILDSYSTEM_PATH)/build_files/OS/$($(PROG_ACY)_OS)_$($(PROG_ACY)_OS_LEVEL)_rules.mk
