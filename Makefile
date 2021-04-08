
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

PROJECT := shook
GIT_COMMIT := $(shell git describe --abbrev=0 --dirty --always --tags)
BUILD_DATE := $(shell date '+%Y%m%d-%H%M%S')
TARGET_ARCH := x86_64

TARGET_PROJECT_CFLAGS := -g -Wall -DPROJECT=$(PROJECT) -DTARGET_ARCH_$(TARGET_ARCH)=1
TARGET_CFLAGS = $(TARGET_PROJECT_CFLAGS) -Wstrict-prototypes -MT $@ -MMD -MP -MF $@.d
TARGET_CXXFLAGS = $(TARGET_PROJECT_CFLAGS) -std=c++11 -MT $@ -MMD -MP -MF $@.d
TARGET_CC = gcc
TARGET_CXX = g++

TARGET_PYTHON_CFLAGS := $(shell pkg-config --cflags python3)
TARGET_PYTHON_LDFLAGS := $(shell pkg-config --libs python3)

TARGET_DIR_out := target.dbg.linux.$(TARGET_ARCH)

TARGET_SET_dir := bin src tests share/shook/scripts

.PHONY: all target_mkdir
TARGET_SET_tests := time getifaddrs thread signal sockaddr
TARGET_SET_scripts := shook_utils stracer netlink

TARGET_SET_lib := 

TARGET_CFLAGS_EXTRA := \
	-D__X_DEVELOPER__=1

all: $(TARGET_DIR_out)/bin/$(PROJECT) \
	$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) \
	$(TARGET_SET_scripts:%=$(TARGET_DIR_out)/share/shook/scripts/%.py)

TARGET_SET_src := main version vdso \
	python syscallent log timerq utils \

$(TARGET_DIR_out)/bin/$(PROJECT): $(TARGET_SET_src:%=$(TARGET_DIR_out)/src/%.o) $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(TARGET_CXX) -g $(TARGET_LDFLAGS) -o $@ $^ $(TARGET_PYTHON_LDFLAGS) -lunwind-x86_64 -lunwind-ptrace

$(TARGET_DIR_out)/src/version.o: src/version.cxx
	$(TARGET_CXX) -c $(TARGET_CXXFLAGS) $(TARGET_PYTHON_CFLAGS) -DGIT_COMMIT=\"$(GIT_COMMIT)\" -DBUILD_DATE=\"$(BUILD_DATE)\" -DBUILD_ARCH=\"$(TARGET_ARCH)\" -o $@ $<

$(TARGET_DIR_out)/src/version.o: $(TARGET_SET_src:%=src/%.cxx)

$(TARGET_DIR_out)/src/%.o: src/%.cxx | target_mkdir
	$(TARGET_CXX) -c $(TARGET_CXXFLAGS) $(TARGET_PYTHON_CFLAGS) -o $@ $<

$(TARGET_SET_src:%=$(TARGET_DIR_out)/src/%.o): Makefile

$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) : %: %.o $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a) | target_mkdir
	$(TARGET_CXX) -g $(TARGET_LDFLAGS) -o $@ $^ -lpthread -lresolv -ldl

$(TARGET_DIR_out)/tests/%.o: tests/%.cxx | target_mkdir
	$(TARGET_CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

TARGET_DEPFILES := $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%.o.d) $(TARGET_SET_src:%=$(TARGET_DIR_out)/src/%.o.d)

$(TARGET_DIR_out)/share/shook/scripts/%.py: scripts/%.py | target_mkdir
	install -m 644 $< $(TARGET_DIR_out)/share/shook/scripts 

include $(wildcard $(TARGET_DEPFILES))

target_mkdir: $(TARGET_SET_dir:%=$(TARGET_DIR_out)/%)

$(TARGET_SET_dir:%=$(TARGET_DIR_out)/%): %:
	mkdir -p $@

.PHONY:
clean:
	rm -rf $(TARGET_DIR_out)

define install_files
	@echo "install files to $(1)"
	install -d $(1)/bin/ $(1)/share/shook/scripts
	install -m 755 $(TARGET_DIR_out)/bin/shook $(1)/bin/
	install -m 644 $(TARGET_SET_scripts:%=scripts/%.py) $(1)/share/shook/scripts 
endef

DESTDIR ?= /usr/local
install: all
	$(call install_files,$(DESTDIR))

tarball: $(TARGET_DIR_out)/shook.tar.gz

$(TARGET_DIR_out)/shook.tar.gz: $(TARGET_DIR_out)/bin/$(PROJECT) $(TARGET_SET_scripts:%=$(TARGET_DIR_out)/share/shook/scripts/%.py)
	tar czf $(TARGET_DIR_out)/shook.tar.gz -C $(TARGET_DIR_out) bin share

test:
	./tests/run-tests $(TARGET_DIR_out)

test: $(TARGET_DIR_out)/bin/$(PROJECT) $(TARGET_SET_scripts:%=$(TARGET_DIR_out)/share/shook/scripts/%.py)
