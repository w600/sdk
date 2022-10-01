#############################################################
#
# Root Level Makefile
#
#############################################################



######################
CSRCS ?= $(wildcard *.c)
ASRCs ?= $(wildcard *.s)
SUBDIRS ?= $(patsubst %/,%,$(dir $(wildcard */Makefile)))

OBJS := $(CSRCS:%.c=$(OBJODIR)/%.o) \
        $(ASRCs:%.s=$(OBJODIR)/%.o)

OLIBS := $(GEN_LIBS:%=$(LIBODIR)/%)

OIMAGES := $(GEN_IMAGES:%=$(IMAGEODIR)/%)

OBINS := $(GEN_BINS:%=$(BINODIR)/%)


#export LIB_EXT;

CFLAGS = $(CCFLAGS) $(DEFINES) $(EXTRA_CCFLAGS) $(INCLUDES)

UNAME_O:=$(shell uname -o)
UNAME_S:=$(shell uname -s)

# default use 1m flash

ifeq ($(FLASH_SIZE), 2M)
	IMG_TYPE:=3
	IMG_START:=100000
else
	IMG_TYPE:=0
	IMG_START:=90000
endif

define ShortcutRule
$(1): .subdirs $(2)/$(1)
endef

define MakeLibrary
DEP_LIBS_$(1) = $$(foreach lib,$$(filter %$(LIB_EXT),$$(COMPONENTS_$(1))),$$(dir $$(lib))$$(LIBODIR)/$$(notdir $$(lib)))
DEP_OBJS_$(1) = $$(foreach obj,$$(filter %.o,$$(COMPONENTS_$(1))),$$(dir $$(obj))$$(OBJODIR)/$$(notdir $$(obj)))
$$(LIBODIR)/$(1)$(LIB_EXT):  $$(BOOT_OBJS) $$(OBJS) $$(DEP_OBJS_$(1)) $$(DEP_LIBS_$(1)) $$(DEPENDS_$(1))
	@mkdir -p $$(LIBODIR)
	$$(if $$(filter %$(LIB_EXT),$$?),mkdir -p $$(EXTRACT_DIR)_$(1))
	$$(if $$(filter %$(LIB_EXT),$$?),cd $$(EXTRACT_DIR)_$(1); $$(foreach lib,$$(filter %$(LIB_EXT),$$?),$$(AR) $(ARFLAGS_2) $$(UP_EXTRACT_DIR)/$$(lib);))
	@$$(AR) $(ARFLAGS) $$@ $$(filter %.o,$$?) $$(if $$(filter %$(LIB_EXT),$$?),$$(EXTRACT_DIR)_$(1)/*.o)
	$$(if $$(filter %$(LIB_EXT),$$?),$$(RM) -r $$(EXTRACT_DIR)_$(1))
endef

define MakeImage
DEP_LIBS_$(1) = $$(foreach lib,$$(filter %$(LIB_EXT),$$(COMPONENTS_$(1))),$$(dir $$(lib))$$(LIBODIR)/$$(notdir $$(lib)))
DEP_OBJS_$(1) = $$(foreach obj,$$(filter %.o,$$(COMPONENTS_$(1))),$$(dir $$(obj))$$(OBJODIR)/$$(notdir $$(obj)))
$$(IMAGEODIR)/$(1).out: $$(BOOT_OBJS) $$(OBJS) $$(DEP_OBJS_$(1)) $$(DEP_LIBS_$(1)) $$(DEPENDS_$(1))
	@mkdir -p $$(IMAGEODIR)
ifeq ($(COMPILE), gcc)
	$(CC) $$(BOOT_OBJS) -Wl,--gc-sections -Wl,--start-group  $$(OBJS) $$(DEP_OBJS_$(1)) $$(DEP_LIBS_$(1)) $$(if $$(LINKFLAGS_$(1)),$$(LINKFLAGS_$(1)),$$(LINKFLAGS_DEFAULT))   -Wl,--end-group  $(MAP) $(INFO) $(LIST) -o $$@ $(LINKFLAGS) 
else
	$(LINK) $(LINKFLAGS)  $$(OBJS) $$(DEP_OBJS_$(1)) $$(DEP_LIBS_$(1)) $$(if $$(LINKFLAGS_$(1)),$$(LINKFLAGS_$(1)),$$(LINKFLAGS_DEFAULT)) $(MAP) $(INFO) $(LIST) -o $$@
endif
endef

$(BINODIR)/%.bin: $(IMAGEODIR)/%.out
	@mkdir -p $(FIRMWAREDIR)
	@mkdir -p $(FIRMWAREDIR)/$(TARGET)
ifeq ($(COMPILE), gcc)
	@$(OBJCOPY) --output-target=binary -S -g -x -X -R .sbss -R .bss -R .reginfo -R .stack $(IMAGEODIR)/$(TARGET).out $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin	
else
	@$(FROMELF) --bin -o  $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin $(IMAGEODIR)/$(TARGET).out  
endif
	@echo "Generate  $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin successully"


ifeq ($(UNAME_S),Linux)
	@echo "linux platform"

	@echo "Building makeimg"
	@gcc $(SDK_TOOLS)/makeimgsource/makeimg.c -lpthread -O2 -o $(SDK_TOOLS)/makeimg
	@gcc $(SDK_TOOLS)/makeimgsource/makeimg_all.c -lpthread -O2 -o $(SDK_TOOLS)/makeimg_all

	@cp $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin.bk
	@gzip -fv $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin
	@mv $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin.bk $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin
	@$(SDK_TOOLS)/makeimg  $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin "$(FIRMWAREDIR)/$(TARGET)/$(TARGET).img" $(IMG_TYPE) 0 "$(FIRMWAREDIR)/version.txt" $(IMG_START) 10100
	@$(SDK_TOOLS)/makeimg  $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin.gz "$(FIRMWAREDIR)/$(TARGET)/$(TARGET)_gz.img" $(IMG_TYPE) 1 "$(FIRMWAREDIR)/version.txt" $(IMG_START) 10100 $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin
	@$(SDK_TOOLS)/makeimg_all "$(FIRMWAREDIR)/secboot.img" "$(FIRMWAREDIR)/$(TARGET)/$(TARGET).img" "$(FIRMWAREDIR)/$(TARGET)/$(TARGET).fls"
else
ifeq ($(UNAME_O),Darwin)
	@echo "don't support mac"
else
	@echo "windows platform"
	@$(SDK_TOOLS)/wm_tool.exe -b $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin -sb $(FIRMWAREDIR)/secboot.img -fc compress -it $(IMG_TYPE) -ua $(IMG_START) -ra 10100 -df -o $(FIRMWAREDIR)/$(TARGET)/$(TARGET)
endif
endif
	@cp $(IMAGEODIR)/$(TARGET).map $(FIRMWAREDIR)/$(TARGET)/$(TARGET).map
	@rm -f $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin
	@rm -f $(FIRMWAREDIR)/$(TARGET)/$(TARGET).bin.gz
	@rm -f $(FIRMWAREDIR)/$(TARGET)/$(TARGET).img
	@rm -f $(FIRMWAREDIR)/$(TARGET)/$(TARGET)_dbg.img
	@echo "use" $(FLASH_SIZE) "flash"
	@echo "Build finish !!!"

all: .subdirs $(BOOT_OBJS) $(OBJS) $(OLIBS) $(OIMAGES) $(OBINS) $(SPECIAL_MKTARGETS)

clean:
	$(foreach d, $(SUBDIRS), $(MAKE) -C $(d) clean;)
	$(RM) -r $(ODIR)

flash:all
	@$(DL_TOOL) -p $(DL_PORT) -b $(DL_BAUD) write_flash $(FIRMWAREDIR)/$(TARGET)/$(TARGET)_gz.img 

flash_all:all
	@$(DL_TOOL) -p $(DL_PORT) -b $(DL_BAUD) write_flash $(FIRMWAREDIR)/$(TARGET)/$(TARGET).fls 

erase:
	@$(DL_TOOL) -p $(DL_PORT) erase_flash

clobber: $(SPECIAL_CLOBBER)
	$(foreach d, $(SUBDIRS), $(MAKE) -C $(d) clobber;)
	$(RM) -r $(ODIR)

.subdirs:
	@set -e; $(foreach d, $(SUBDIRS), $(MAKE) -C $(d);)

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),clobber)
ifdef DEPS
sinclude $(DEPS)
endif
endif
endif

$(OBJODIR)/%.o: %.c
	#@mkdir -p $(OBJODIR);
	@mkdir -p $(dir $(@))
	$(CC) $(if $(findstring $<,$(DSRCS)),$(DFLAGS),$(CFLAGS)) $(COPTS_$(*F)) $(INCLUDES) $(CMACRO) -c -o $@  $<

ifeq ($(COMPILE), gcc)
$(OBJODIR)/%.o: %.s
	@mkdir -p $(OBJODIR);
	$(ASM) $(ASMFLAGS) $(INCLUDES) $(CMACRO) -c -o $@ $<
else
$(OBJODIR)/%.o: %.s
	@mkdir -p $(OBJODIR);
	$(ASM) $(ASMFLAGS) $(INCLUDES) $(CMACRO) -o $@ $<
endif

$(foreach lib,$(GEN_LIBS),$(eval $(call ShortcutRule,$(lib),$(LIBODIR))))

$(foreach image,$(GEN_IMAGES),$(eval $(call ShortcutRule,$(image),$(IMAGEODIR))))

$(foreach bin,$(GEN_BINS),$(eval $(call ShortcutRule,$(bin),$(BINODIR))))

$(foreach lib,$(GEN_LIBS),$(eval $(call MakeLibrary,$(basename $(lib)))))

$(foreach image,$(GEN_IMAGES),$(eval $(call MakeImage,$(basename $(image)))))

INCLUDES := $(INC) $(INCLUDES) -I $(PDIR)include
#PDIR := ../$(PDIR)
#sinclude $(PDIR)Makefile

ifeq ($(COMPILE), gcc)
INCLUDES += -I $(TOP_DIR)/platform/boot/gcc
else
INCLUDES += -I $(TOP_DIR)/include/armcc
INCLUDES += -I $(TOP_DIR)/platform/boot/armcc
endif
INCLUDES += -I $(TOP_DIR)/include
INCLUDES += -I $(TOP_DIR)/include/app
INCLUDES += -I $(TOP_DIR)/include/driver
INCLUDES += -I $(TOP_DIR)/include/net
INCLUDES += -I $(TOP_DIR)/include/os
INCLUDES += -I $(TOP_DIR)/include/platform
INCLUDES += -I $(TOP_DIR)/include/wifi

INCLUDES += -I $(TOP_DIR)/platform/common/crypto
INCLUDES += -I $(TOP_DIR)/platform/common/crypto/digest
INCLUDES += -I $(TOP_DIR)/platform/common/crypto/keyformat
INCLUDES += -I $(TOP_DIR)/platform/common/crypto/math
INCLUDES += -I $(TOP_DIR)/platform/common/crypto/prng
INCLUDES += -I $(TOP_DIR)/platform/common/crypto/pubkey
INCLUDES += -I $(TOP_DIR)/platform/common/crypto/symmetric
INCLUDES += -I $(TOP_DIR)/platform/common/Params
INCLUDES += -I $(TOP_DIR)/platform/inc
INCLUDES += -I $(TOP_DIR)/platform/sys
INCLUDES += -I $(TOP_DIR)/src/network/api2.0.3
INCLUDES += -I $(TOP_DIR)/src/wlan/driver
INCLUDES += -I $(TOP_DIR)/src/wlan/supplicant
INCLUDES += -I $(TOP_DIR)/src/app/wm_atcmd
INCLUDES += -I $(TOP_DIR)/src/app/demo
INCLUDES += -I $(TOP_DIR)/src/app/dhcpserver
INCLUDES += -I $(TOP_DIR)/src/app/dnsserver
INCLUDES += -I $(TOP_DIR)/src/app/matrixssl
INCLUDES += -I $(TOP_DIR)/src/app/matrixssl/crypto
INCLUDES += -I $(TOP_DIR)/src/app/libupnp-1.6.19/ixml/inc
INCLUDES += -I $(TOP_DIR)/src/app/libupnp-1.6.19/upnp/inc
INCLUDES += -I $(TOP_DIR)/src/app/libupnp-1.6.19/ixml/include
INCLUDES += -I $(TOP_DIR)/src/app/libupnp-1.6.19/threadutil/include
INCLUDES += -I $(TOP_DIR)/src/app/libupnp-1.6.19/upnp/include
INCLUDES += -I $(TOP_DIR)/src/app/gmediarender-0.0.6
INCLUDES += -I $(TOP_DIR)/src/app/web
INCLUDES += -I $(TOP_DIR)/src/app/cloud
#INCLUDES += -I $(TOP_DIR)/src/app/cjson
INCLUDES += -I $(TOP_DIR)/src/app/ajtcl-15.04.00a/inc
INCLUDES += -I $(TOP_DIR)/src/app/ajtcl-15.04.00a/target/winnermicro
INCLUDES += -I $(TOP_DIR)/src/app/ajtcl-15.04.00a/external/sha2
#INCLUDES += -I $(TOP_DIR)/src/app/cjson
INCLUDES += -I $(TOP_DIR)/src/app/cloud/kii
INCLUDES += -I $(TOP_DIR)/src/app/rmms
INCLUDES += -I $(TOP_DIR)/src/app/ntp
INCLUDES += -I $(TOP_DIR)/src/os/os_ports
INCLUDES += -I $(TOP_DIR)/src/app/httpclient
INCLUDES += -I $(TOP_DIR)/src/app/oneshotconfig
INCLUDES += -I $(TOP_DIR)/src/app/iperf
INCLUDES += -I $(TOP_DIR)/src/os/ucos-ii
INCLUDES += -I $(TOP_DIR)/src/os/ucos-ii/ports
INCLUDES += -I $(TOP_DIR)/src/os/ucos-ii/source
INCLUDES += -I $(TOP_DIR)/src/os/rtos/include
INCLUDES += -I $(TOP_DIR)/src/app/matrixssl/core
INCLUDES += -I $(TOP_DIR)/src/app/mqtt
INCLUDES += -I $(TOP_DIR)/src/app/iperf
INCLUDES += -I $(TOP_DIR)/src/app/ping
INCLUDES += -I $(TOP_DIR)/src/app/polarssl/include
INCLUDES += -I $(TOP_DIR)/src/app/mdns/mdnsposix
INCLUDES += -I $(TOP_DIR)/src/app/mdns/mdnscore
INCLUDES += -I $(TOP_DIR)/src/network/lwip2.0.3/include
INCLUDES += -I $(TOP_DIR)/src/app/ota
INCLUDES += -I $(TOP_DIR)/src/app/libwebsockets-2.1-stable
INCLUDES += -I $(TOP_DIR)/src/app/easylogger/inc

INCLUDES += -I $(TOP_DIR)/demo
INCLUDES += -I $(TOP_DIR)/lib
