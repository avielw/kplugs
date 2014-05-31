OBJECTS := cache.o calling.o calling_wrapper.o context.o env.o function.o kplugs.o memory.o stack.o vm.o

RELEASE_DIR :=	Release
DEBUG_DIR :=	Debug


$(RELEASE_DIR)/kplugs_release-objs = $(OBJECTS)
$(DEBUG_DIR)/kplugs_debug-objs = $(OBJECTS)

MAKECMD := make -C "/lib/modules/`uname -r`/build" SUBDIRS=$(PWD)
CPPFLAGS := -Wall -x assembler-with-cpp
MKDIR := mkdir

all:
	@if [ -d $(DEBUG_DIR) ]; then echo "$(DEBUG_DIR) directory already exists";  else $(MKDIR) $(DEBUG_DIR); fi
	@if [ -d $(RELEASE_DIR) ]; then echo "$(RELEASE_DIR) directory already exists";  else $(MKDIR) $(RELEASE_DIR); fi

	@$(MAKECMD) obj-m="$(RELEASE_DIR)/kplugs_release.o" modules
	@$(MAKECMD) obj-m="$(DEBUG_DIR)/kplugs_debug.o" EXTRA_CFLAGS="-DDEBUG" modules

	@rm -f $(OBJECTS)
clean:
	@$(MAKECMD) clean

