CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O3
LDFLAGS = -lz -lcryptopp -lre2

# Detect OS
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
    # macOS specific settings
    CXX = clang++
    CXXFLAGS += -stdlib=libc++
    
    # Check for Apple Silicon
    ifeq ($(UNAME_M),arm64)
        # Apple Silicon paths
        LDFLAGS += -L/opt/homebrew/lib
        INCLUDES = -I/opt/homebrew/include -I/opt/homebrew/opt/cryptopp/include -I/opt/homebrew/opt/re2/include
    else
        # Intel Mac paths
        LDFLAGS += -L/usr/local/lib
        INCLUDES = -I/usr/local/include -I/usr/local/opt/cryptopp/include -I/usr/local/opt/re2/include
    endif
else
    # Linux specific settings
    INCLUDES = -I/usr/include
endif

SRC = main.cpp $(wildcard src/*.cpp)
OBJ = $(SRC:.cpp=.o)
TARGET = pka2xml

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

# macOS specific targets
install-macos: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall-macos:
	rm -f /usr/local/bin/$(TARGET)

# Docker specific targets (kept for compatibility)
static-install-docker:
	$(CXX) $(CXXFLAGS) -static -o $(TARGET) $(SRC) $(LDFLAGS)
	install -m 755 $(TARGET) /usr/local/bin/
