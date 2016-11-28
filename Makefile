
RELEASE_DIR :=  Release
DEBUG_DIR   :=  Debug

MKDIR  := mkdir
REMOVE := rm
MAKE   := make
COPY   := cp

all:
	@if [ -d $(DEBUG_DIR) ]; then echo "$(DEBUG_DIR) directory already exists";  else $(MKDIR) $(DEBUG_DIR); fi
	@if [ -d $(RELEASE_DIR) ]; then echo "$(RELEASE_DIR) directory already exists";  else $(MKDIR) $(RELEASE_DIR); fi

	cp Makefile.release $(RELEASE_DIR)/Makefile
	cp Makefile.debug   $(DEBUG_DIR)/Makefile

	$(COPY) *.c *.S *.h $(RELEASE_DIR)
	$(COPY) *.c *.S *.h $(DEBUG_DIR)

	@cd $(RELEASE_DIR); $(MAKE)
	@cd $(DEBUG_DIR); $(MAKE)
clean:
	@if [ -d $(RELEASE_DIR) ]; then cd $(RELEASE_DIR); $(MAKE) clean ; fi
	@$(REMOVE) -rf $(RELEASE_DIR)

	@if [ -d $(DEBUG_DIR) ]; then cd $(DEBUG_DIR); $(MAKE) clean ; fi
	@$(REMOVE) -rf $(DEBUG_DIR)

