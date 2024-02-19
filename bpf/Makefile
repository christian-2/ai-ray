
.PHONY: all clean

NDEBUG=

SUBDIRS := $(shell ls -d */)

all:
	for dir in $(SUBDIRS); do make -C $$dir NDEBUG=$(NDEBUG); done

clean:
	for dir in $(SUBDIRS); do make -C $$dir clean; done
