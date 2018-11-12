# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=cfi

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+=-O0 -g 
CXXFLAGS+=-std=c++11 -O3
# LIBS+=


# OBJS=cfi.o recon.o extract_from_binary.o libdasm.o

# Object files comprising the plugin.
PLUGIN_OBJFILES=$(PLUGIN_OBJ_DIR)/extract_from_binary.o\
				$(PLUGIN_OBJ_DIR)/libdasm.o\
				$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o			
				# $(PLUGIN_OBJ_DIR)/procmod.o\
				# $(PLUGIN_OBJ_DIR)/function_map.o\
				#$(PLUGIN_OBJ_DIR)/callback.o
				#$(PLUGIN_OBJ_DIR)/recon.o\

.PHONY: all

# Plugin dynamic library. Please stick with the panda_ naming convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $@ $^ $(LDFLAGS) $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_OBJ_DIR) $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
