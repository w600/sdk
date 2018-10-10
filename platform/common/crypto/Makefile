
#############################################################
# Required variables for each makefile
# Discard this section from all parent makefiles
# Expected variables (with automatic defaults):
#   CSRCS (all "C" files in the dir)
#   SUBDIRS (all subdirs with a Makefile)
#   GEN_LIBS - list of libs to be generated ()
#   GEN_IMAGES - list of images to be generated ()
#   COMPONENTS_xxx - a list of libs/objs in the form
#     subdir/lib to be extracted and rolled up into
#     a generated lib/image xxx.a ()
#
TOP_DIR = ../../../
sinclude $(TOP_DIR)/tools/tool_chain.def

ifndef PDIR
UP_EXTRACT_DIR = ..
GEN_LIBS = libcrypto$(LIB_EXT)
COMPONENTS_libcrypto =  digest/libdigest$(LIB_EXT) 	\
						keyformat/libkeyformat$(LIB_EXT)	\
						math/libmath$(LIB_EXT)	\
						prng/libprng$(LIB_EXT)	\
						pubkey/libpubkey$(LIB_EXT)	\
						symmetric/libsymmetric$(LIB_EXT)
endif


#############################################################
# Configuration i.e. compile options etc.
# Target specific stuff (defines etc.) goes in here!
# Generally values applying to a tree are captured in the
#   makefile at its root level - these are then overridden
#   for a subtree within the makefile rooted therein
#
#DEFINES += 

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
sinclude $(TOP_DIR)/tools/rules.mk
INCLUDES := $(INCLUDES) -I ./ -I $(PDIR)include
PDIR := ../$(PDIR)
sinclude $(PDIR)Makefile

