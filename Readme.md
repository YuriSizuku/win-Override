# Override (rePatch)

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/yurisizuku/win-Override?color=green&label=Override)![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/YuriSizuku/win-Override/build.yml?label=build)  

☘️ Tools for windows game mod (localization) without cover origin file.  
See also [psv-rePatch](https://github.com/YuriSizuku/psv-rePatch).  

## components  

`winloader.c`, win loader for loading dll into exe  
`libwinversion.c`, single header file for windows version.dll proxy to patch.dll  
`libwinoverride.c`, redirct files to "override" folder  

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
