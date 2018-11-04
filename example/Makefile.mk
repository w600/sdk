#############################################################
# Required variables for each makefile
# Discard this section from all parent makefiles
# Expected variables (with automatic defaults):
#   CSRCS (all "C" files in the dir)
#   SUBDIRS (all subdirs with a Makefile)
#   GEN_LIBS - list of libs to be generated ()
#   GEN_IMAGES - list of object file images to be generated ()
#   GEN_BINS - list of binaries to be generated ()
#   COMPONENTS_xxx - a list of libs/objs in the form
#     subdir/lib to be extracted and rolled up into
#     a generated lib/image xxx.a ()
#

TOP_DIR:=../
sinclude $(TOP_DIR)/tools/tool_chain.def

APP_BIN_NAME?=at

#EXTRA_CCFLAGS += -u
ifndef PDIR # {
GEN_IMAGES= $(TARGET).out
GEN_BINS = $(TARGET).bin
SUBDIRS += 	\
	$(TOP_DIR)/example/$(APP_BIN_NAME)/user	\
	$(TOP_DIR)/platform/boot/$(COMPILE)
endif # } PDIR

COMPONENTS_$(TARGET) =	\
	$(TOP_DIR)/platform/boot/$(COMPILE)/startup.o	\
	$(TOP_DIR)/platform/boot/$(COMPILE)/misc.o	\
	$(TOP_DIR)/platform/boot/$(COMPILE)/retarget.o	\
	$(TOP_DIR)/example/$(APP_BIN_NAME)/user/libuser$(LIB_EXT)

ifeq ($(COMPILE), gcc)
LINKFLAGS_$(TARGET) =  \
	$(TOP_DIR)/lib/wlan$(LIB_EXT) \
	$(TOP_DIR)/lib/libcommon$(LIB_EXT) \
	$(TOP_DIR)/lib/libdrivers$(LIB_EXT)	\
	$(TOP_DIR)/lib/libsys$(LIB_EXT)	\
	$(TOP_DIR)/lib/libairkiss_log$(LIB_EXT)	\
	$(TOP_DIR)/lib/libapp$(LIB_EXT)	\
	$(TOP_DIR)/lib/libnetwork$(LIB_EXT)	\
	$(TOP_DIR)/lib/libos$(LIB_EXT)  \
	-T$(LD_FILE)	\
	-Wl,-warn-common 	

else
LINKFLAGS_$(TARGET) = 	\
	--library_type=microlib	\
	$(TOP_DIR)/lib/wlan$(LIB_EXT) \
	$(TOP_DIR)/lib/libcommon$(LIB_EXT) \
	$(TOP_DIR)/lib/libdrivers$(LIB_EXT)	\
	$(TOP_DIR)/lib/libsys$(LIB_EXT)	\
	$(TOP_DIR)/lib/libairkiss_log$(LIB_EXT)	\
	$(TOP_DIR)/lib/libapp$(LIB_EXT)	\
	$(TOP_DIR)/lib/libnetwork$(LIB_EXT)	\
	$(TOP_DIR)/lib/libos$(LIB_EXT)  \
	--strict --scatter $(LD_FILE)
endif

#############################################################
# Configuration i.e. compile options etc.
# Target specific stuff (defines etc.) goes in here!
# Generally values applying to a tree are captured in the
#   makefile at its root level - these are then overridden
#   for a subtree within the makefile rooted therein
#

CONFIGURATION_DEFINES += -DWM_W600

DEFINES +=				\
	$(CONFIGURATION_DEFINES)

DDEFINES +=				\
	$(CONFIGURATION_DEFINES)

CCFLAGS += 				\
	$(CONFIGURATION_DEFINES)

#############################################################
# Recursion Magic - Don't touch this!!
#
# Each subtree potentially has an include directory
#   corresponding to the common APIs applicable to modules
#   rooted at that subtree. Accordingly, the INCLUDE PATH
#   of a module can only contain the include directories up
#   its parent path, and not its siblings
#
# Required for each makefile to inherit from the parent
#

INCLUDES := $(INCLUDES) -I$(PDIR)include
INCLUDES += -I ./
INCLUDES += -I $(TOP_DIR)/example/$(APP_BIN_NAME)/include/ -I $(TOP_DIR)/example/$(APP_BIN_NAME)/user/
#PDIR := ../$(PDIR)
#sinclude $(PDIR)Makefile

sinclude $(TOP_DIR)/tools/rules.mk

.PHONY: FORCE
FORCE:
