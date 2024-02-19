
.PHONY: all clean gofmt test

export KERNEL_RELEASES := "6.1.0-16-amd64"

SUBDIRS := $(shell ls -d */ | grep -vE '(docs|pkg)/' | sed 's/\/$$//')

TARGET := ai-ray

all: $(TARGET)

$(TARGET) : $(shell if [ -f $(TARGET) ]; then \
	find . -name '*'.go -newer $(TARGET); else find . -name '*'.go; fi) \
	pkg/module/mem/maps_gen.go
	make -C bpf
	go build -ldflags "-X main.KERNEL_RELEASES=$(KERNEL_RELEASES)" -o $@

pkg/module/mem/maps_gen.go: pkg/module/mem/maps.go
	go tool cgo -godefs $< > $@

clean:
	rm -f $(TARGET)
	make -C bpf clean
	go clean -r github.com/christian-2/ai-ray
	rm -f pkg/module/*/maps_gen.go

gofmt:
	gofmt -d main.go pkg

test:
	go test ./...
