
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

PROJECT := shook
VERSION := 0.1
TARGET_ARCH := x86_64

TARGET_PROJECT_CFLAGS := -g -Wall -DPROJECT=$(PROJECT) -DTARGET_ARCH_$(TARGET_ARCH)=1
TARGET_CFLAGS = $(TARGET_PROJECT_CFLAGS) -Wstrict-prototypes -MT $@ -MMD -MP -MF $@.d
TARGET_CXXFLAGS = $(TARGET_PROJECT_CFLAGS) -std=c++11 -MT $@ -MMD -MP -MF $@.d
TARGET_CC = gcc
TARGET_CXX = g++

TARGET_PYTHON_CFLAGS := $(shell pkg-config --cflags python3)
TARGET_PYTHON_LDFLAGS := $(shell pkg-config --libs python3)

TARGET_DIR_out := target.dbg.linux.$(TARGET_ARCH)

TARGET_SET_dir := bin src tests

.PHONY: all target_mkdir
TARGET_SET_tests := time getifaddrs

TARGET_SET_lib := 

TARGET_CFLAGS_EXTRA := \
	-D__X_DEVELOPER__=1

all: $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) $(TARGET_DIR_out)/bin/$(PROJECT)

TARGET_SET_src := main vdso \
	python syscallent log timerq utils \

$(TARGET_DIR_out)/bin/$(PROJECT): $(TARGET_SET_src:%=$(TARGET_DIR_out)/src/%.o) $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a)
	$(TARGET_CXX) -g $(TARGET_LDFLAGS) -o $@ $^ $(TARGET_PYTHON_LDFLAGS) -lunwind-x86_64 -lunwind-ptrace

$(TARGET_DIR_out)/src/%.o: src/%.cxx | target_mkdir
	$(TARGET_CXX) -c $(TARGET_CXXFLAGS) $(TARGET_PYTHON_CFLAGS) -o $@ $<

#$(TARGET_SET_src:%=$(TARGET_DIR_out)/src/%.o): $(TARGET_DIR_out)/%.o: %.cxx | target_mkdir
#	$(TARGET_CXX) -c $(TARGET_CXXFLAGS) $(TARGET_PYTHON_CFLAGS) -o $@ $<
#
$(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%) : %: %.o $(TARGET_SET_lib:%=$(TARGET_DIR_out)/lib%.a) | target_mkdir
	$(TARGET_CXX) -g $(TARGET_LDFLAGS) -o $@ $^ -lpthread -lresolv -ldl

$(TARGET_DIR_out)/tests/%.o: tests/%.cxx | target_mkdir
	$(TARGET_CXX) -c $(TARGET_CXXFLAGS) $(TARGET_CFLAGS_EXTRA) -o $@ $<

TARGET_DEPFILES := $(TARGET_SET_tests:%=$(TARGET_DIR_out)/tests/%.o.d) $(TARGET_SET_src:%=$(TARGET_DIR_out)/src/%.o.d)

include $(wildcard $(TARGET_DEPFILES))

target_mkdir: $(TARGET_SET_dir:%=$(TARGET_DIR_out)/%)

$(TARGET_SET_dir:%=$(TARGET_DIR_out)/%): %:
	mkdir -p $@

.PHONY:
clean:
	rm -rf $(TARGET_DIR_out)

SCRIPTS := stracer.py netlink.py shook_utils.py
DESTDIR ?= /usr/local
install: all
	install -d $(DESTDIR)/bin/ $(DESTDIR)/share/shook/scripts
	install -m 755 $(TARGET_DIR_out)/bin/shook $(DESTDIR)/bin/
	install -m 644 $(SCRIPTS:%=scripts/%) $(DESTDIR)/share/shook/scripts 
