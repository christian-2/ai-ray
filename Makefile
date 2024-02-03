
.PHONY: all clean gofmt

export KERNEL_RELEASES := "6.1.0-16-amd64"

SUBDIRS := $(shell ls -d */ | grep -vE '(docs|pkg)/' | sed 's/\/$$//')

all:
	for dir in $(SUBDIRS); do make -C $$dir; done

test:
	go test ./...

clean:
	for dir in $(SUBDIRS); do make -C $$dir clean; done

gofmt:
	gofmt -d cmd pkg
