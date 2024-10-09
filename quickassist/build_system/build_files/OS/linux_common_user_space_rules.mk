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

ifeq ($($(PROG_ACY)_OS_LEVEL), user_space)

# Compile the object files with the CFLAGS
$(OBJECTS): %.o: %.c
	@$(COMPILER) $(CFLAGS) $(EXTRA_CFLAGS) -c $(PWD)/$< -o $($(PROG_ACY)_FINAL_OUTPUT_DIR)/$@


# Create the shared library
$(LIB_SHARED): obj
	@cd $($(PROG_ACY)_FINAL_OUTPUT_DIR); \
	$(LINKER) $(LIB_SHARED_FLAGS) -o $@  $(OBJECTS) $(ADDITIONAL_OBJECTS) -lc


# Create the static library
$(LIB_STATIC): obj
	@cd $($(PROG_ACY)_FINAL_OUTPUT_DIR); \
	$(ARCHIVER) $(LIB_STATIC_FLAGS) r $@ $(OBJECTS) $(ADDITIONAL_OBJECTS)


#Create executable output
$(EXECUTABLE):  obj
	@cd $($(PROG_ACY)_FINAL_OUTPUT_DIR); \
	$(COMPILER) -o $@  $(OBJECTS) $(ADDITIONAL_OBJECTS) $(EXE_FLAGS)


$(MODULENAME):
	@echo Error: $@: You cannot build modules in user_space;

endif

ifneq ($($(PROG_ACY)_DEBUG),y)
-include $($(PROG_ACY)_BUILDSYSTEM_PATH)/build_files/defenses.mk
endif
