# build example, tested in linux 10.0.0-3, gcc 12, wine-9.0
# make libwinoverride CC=i686-w64-mingw32-gcc BUILD_TYPE=32d 
# make libwinoverride CC=x86_64-w64-mingw32-gcc BUILD_TYPE=64d

# general config
CC:=gcc # clang (llvm-mingw), gcc (mingw-w64), tcc (x86 stdcall name has problem)
BUILD_TYPE:=32
BUILD_DIR:=build
INCS:=-Isrc -Idepend/winreverse/src -Idepend/minhookstb/src
LIBS:=-lgdi32
CFLAGS:=-fPIC -std=gnu99 \
	-fvisibility=hidden \
	-ffunction-sections -fdata-sections
LDFLAGS:=-Wl,--gc-sections \
		 -D_WIN32_WINNT=0X0400 \
		 -Wl,--subsystem,console:4.0 # compatible for xp

# build config
ifneq (,$(findstring 64, $(BUILD_TYPE)))
CFLAGS+=-m64
else
CFLAGS+=-m32
endif
ifneq (,$(findstring d, $(BUILD_TYPE)))
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif

ifneq (,$(findstring clang, $(CC))) # for llvm-mingw
ifdef USEPDB
CFLAGS+=-gcodeview -Wl,--pdb=$(BUILD_DIR)/libwinoverride.pdb
endif
else ifneq (,$(findstring gcc, $(CC))) # for mingw-w64
LDFLAGS+=-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
else ifneq (,$(findstring tcc, $(CC))) # for tcc
LDFLAGS= # tcc can not remove at at stdcall in i686, can not use .def
endif

all: prepare libwinoverride

clean:
	@rm -rf $(BUILD_DIR)/*libwinoverride*

prepare:
	@if ! [ -d $(BUILD_DIR) ]; then mkdir -p $(BUILD_DIR); fi

libwinoverride: src/libwinoverride.c src/libwinoverride.def
	@echo "## $@"
	$(CC) $^ -shared -o $(BUILD_DIR)/$@$(BUILD_TYPE).dll \
		$(INCS) $(LIBS) \
		$(CFLAGS) $(LDFLAGS)

.PHONY: all clean prepare libwinoverride