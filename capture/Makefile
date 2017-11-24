# root directory
ROOT_DIR = $(shell pwd)

# sub directory
SUBDIRS = 

#some display variables
NORMAL="\\033[0;39m"
SUCCESS="\\033[1;32m"
FAILURE="\\033[1;31m"

#targets
LIBTARGET = libcapture.so 

#objects
OBJS = capture.o 

#special CFLAGS 
CFLAGS += -fPIC

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY:all
all:lib

lib:$(LIBTARGET)

$(LIBTARGET):$(OBJS)
	$(CC) $(CFLAGS) -fPIC -shared -o $(LIBTARGET) $(OBJS) 
	@echo -en $(SUCCESS);
	@echo "make lib success"
	@echo -en $(NORMAL);

install: $(LIBTARGET)
	@mkdir -p $(FIRM_LIB_DIR)
	@cd $(TOPDIR) && $(CP) $(LIBTARGET) $(FIRM_LIB_DIR)
	@echo -en $(SUCCESS);
	@echo "install successfully";
	@echo -en $(NORMAL);

clean:
	@rm -fr $(LIBTARGET) $(OBJS)
	@echo -en $(SUCCESS);
	@echo "make clean successfully"
	@echo -en $(NORMAL);
