# root directory
ROOT_DIR = $(shell pwd)

#some display variables
NORMAL="\\033[0;39m"
SUCCESS="\\033[1;32m"
FAILURE="\\033[1;31m"

# sub directory
SUBDIRS = common capture flow dissector

# sniffer library
SNIFFER_LIB = 

# DPDK 17.02 
DPDK_INCLUDE_PATH = ${RTE_SDK}/${RTE_TARGET}/include 
DPDK_LIB_PATH = ${RTE_SDK}/${RTE_TARGET}/lib

DPDK_LIBS = $(DPDK_LIB_PATH)/librte_ethdev.a \
$(DPDK_LIB_PATH)/librte_acl.a	\
$(DPDK_LIB_PATH)/librte_pmd_af_packet.a	\
$(DPDK_LIB_PATH)/librte_cfgfile.a	\
$(DPDK_LIB_PATH)/librte_cmdline.a	\
$(DPDK_LIB_PATH)/librte_distributor.a \
$(DPDK_LIB_PATH)/librte_eal.a	\
$(DPDK_LIB_PATH)/librte_hash.a	\
$(DPDK_LIB_PATH)/librte_ip_frag.a	\
$(DPDK_LIB_PATH)/librte_jobstats.a	\
$(DPDK_LIB_PATH)/librte_kni.a	\
$(DPDK_LIB_PATH)/librte_kvargs.a	\
$(DPDK_LIB_PATH)/librte_lpm.a	\
$(DPDK_LIB_PATH)/librte_mbuf.a	\
$(DPDK_LIB_PATH)/librte_mempool.a	\
$(DPDK_LIB_PATH)/librte_meter.a	\
$(DPDK_LIB_PATH)/librte_pipeline.a	\
$(DPDK_LIB_PATH)/librte_pmd_bond.a	\
$(DPDK_LIB_PATH)/librte_pmd_e1000.a	\
$(DPDK_LIB_PATH)/librte_pmd_enic.a	\
$(DPDK_LIB_PATH)/librte_pmd_fm10k.a	\
$(DPDK_LIB_PATH)/librte_pmd_i40e.a	\
$(DPDK_LIB_PATH)/librte_pmd_ixgbe.a	\
$(DPDK_LIB_PATH)/librte_pmd_null.a	\
$(DPDK_LIB_PATH)/librte_pmd_ring.a	\
$(DPDK_LIB_PATH)/librte_pmd_vmxnet3_uio.a	\
$(DPDK_LIB_PATH)/librte_port.a	\
$(DPDK_LIB_PATH)/librte_power.a	\
$(DPDK_LIB_PATH)/librte_reorder.a	\
$(DPDK_LIB_PATH)/librte_ring.a	\
$(DPDK_LIB_PATH)/librte_sched.a	\
$(DPDK_LIB_PATH)/librte_table.a	\
$(DPDK_LIB_PATH)/librte_timer.a

# src file
SRC = sniffer.c 

# compilation
INCLUDE_DIR = -I$(DPDK_INCLUDE_PATH)
LDFLAGS =  -Wl,--whole-archive -lpthread $(DPDK_LIBS) $(ROOT_DIR)/common/libcommon.so $(ROOT_DIR)/capture/libcapture.so \
$(ROOT_DIR)/flow/libflow.so $(ROOT_DIR)/dissector/libdissector.so \
-lrt -lm -ldl  -Wl,--no-whole-archive
CFLAGS = -Wall -Wextra -ffunction-sections -include $(RTE_SDK)/${RTE_TARGET}/include/rte_config.h -msse4.2 $(INCLUDE_DIR)  -march=native

# optmimization
ifdef O3
CFLAGS += -O3
 ifndef CHECKOFF
 CHECKOFF = 1
 endif
else
CFLAGS += -g
endif

# main cflags
MCFLAGS = $(CFLAGS)

#compiler variable
CC              = $(CROSS_COMPILE)gcc
CXX             = $(CROSS_COMPILE)g++
AR              = $(CROSS_COMPILE)ar
AS              = $(CROSS_COMPILE)as
LD              = $(CROSS_COMPILE)ld
RANLIB  = $(CROSS_COMPILE)ranlib
NM              = $(CROSS_COMPILE)nm
STRIP   = $(CROSS_COMPILE)strip
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump

# To make it visible
export CXX CXXPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR

all: subdir dpdk_sniffer

help:
	@echo " "

# version name
ifndef VER
VER = $(shell date +%Y_%m_%d)
endif

subdir:
	@for dir in $(SUBDIRS) ; \
           do $(MAKE) -C $$dir || exit 1; \
         done

dpdk_sniffer: $(SRC:.c=.o) $(DPDK_LIBS)
	$(CC) $(MCFLAGS) -o $@ $(SRC:.c=.o) $(LDFLAGS) 
	@echo -en $(SUCCESS);
	@echo "make dpdk_sniffer success"
	@echo -en $(NORMAL);
	
clean: 
	@for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir clean; done
	rm -f dpdk_sniffer *.o *~ log.* .depend val.* *.expand 
	@echo -en $(SUCCESS);
	@echo "make clean successfully"
	@echo -en $(NORMAL);
	
%.o: %.c
	$(CC) $(MCFLAGS) -c -o $@ $< 


.depend: $(SRC)
	$(CC) -M $(MCFLAGS) $(SRC) > $@


sinclude .depend