# Override (rePatch)

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/yurisizuku/win-Override?color=green&label=Override)![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/YuriSizuku/win-Override/build.yml?label=build)  

☘️ Tools for windows game mod (localization) without covering origin files.  
See also [psv-rePatch](https://github.com/YuriSizuku/psv-rePatch).  

## components  

`winloader.c`, win loader for loading dll into exe  
`winversion.h`, single header file for windows version.dll proxy to patch.dll  
`winoverride.h`, single header file for redircting files to "override" folder  

## usage

### winloader

rename `winloader32.exe` or `winloader64.exe` to `xxx_yyy.exe`, and it will automaticly load `xxx.dll`

### winversion  

rename `libwinversion32.dll` or `libwinversion64.dll` to `version.dll`, and it will automaticly load `patch.dll`.  

### winoverride

load `libwinoverride32.dll` or `libwinoverride64.dll` into target exe either by `winloader` or `winoverride`, and it will automaticly redirect `${pwd}/xxx/yyy` to `${pwd}/override/xxx/yyy` if it exists.  

## build

### llvm-mingw

```sh
make -f winloader.mk CC=i686-w64-mingw32-gcc WINDRES=i686-w64-mingw32-windres BUILD_TYPE=32
make -f winloader.mk CC=x86_64-w64-mingw32-gcc WINDRES=x86_64-w64-mingw32-windres BUILD_TYPE=64
make -f libwinversion.mk CC=i686-w64-mingw32-gcc BUILD_TYPE=32
make -f libwinversion.mk CC=x86_64-w64-mingw32-gcc BUILD_TYPE=64
make -f libwinoverride.mk CC=i686-w64-mingw32-gcc BUILD_TYPE=32
make -f libwinoverride.mk CC=x86_64-w64-mingw32-gcc BUILD_TYPE=64
```

### msvc

``` sh
msbuild winloader.vcxproj -p:configuration=release -p:Platform=x86
msbuild winloader.vcxproj -p:configuration=release -p:Platform=x64
msbuild libwinversion.vcxproj -p:configuration=release -p:Platform=x86
msbuild libwinversion.vcxproj -p:configuration=release -p:Platform=x64
msbuild libwinoverride.vcxproj -p:configuration=release -p:Platform=x86
msbuild libwinoverride.vcxproj -p:configuration=release -p:Platform=x64
```

## issues (including solved)

- [x] unity resources.assets can not be redirect if larger than original file
      caused by `NtQueryFullAttributesFile`
