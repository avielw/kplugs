
RELEASE_DIR :=  Release
DEBUG_DIR   :=  Debug

MKDIR  := mkdir
REMOVE := rm
MAKE   := make
COPY   := cp

define check_dir
	if [ ! -d $(1) ]; then $(MKDIR) $(1); cp Makefile.$(2)   $(1)/Makefile; $(COPY) *.c *.S *.h $(1) ; fi
endef

all: debug release


debug:
	$(call check_dir,$(DEBUG_DIR),debug)
	@cd $(DEBUG_DIR); $(MAKE)

release:
	$(call check_dir,$(RELEASE_DIR),release)
	@cd $(RELEASE_DIR); $(MAKE)

clean:
	@if [ -d $(RELEASE_DIR) ]; then cd $(RELEASE_DIR); $(MAKE) clean ; fi
	@$(REMOVE) -rf $(RELEASE_DIR)

	@if [ -d $(DEBUG_DIR) ]; then cd $(DEBUG_DIR); $(MAKE) clean ; fi
	@$(REMOVE) -rf $(DEBUG_DIR)

