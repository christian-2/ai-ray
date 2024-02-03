
.PHONY: all clean

TARGET := ai-ray

all: $(TARGET)

$(TARGET): $(shell if [ -f $(TARGET) ]; then \
      	find .. -name '*'.go -newer $(TARGET); else find .. -name '*'.go; fi) 
	go build -ldflags "-X main.KERNEL_RELEASES=$(KERNEL_RELEASES)" -o $@

clean:
	go clean
	rm -f $(TARGET)
