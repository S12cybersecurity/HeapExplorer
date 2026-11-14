@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" amd64
if errorlevel 1 (
    echo [!] Failed to set up MSVC environment
    exit /b 1
)

echo [*] MSVC environment ready
cl 2>&1 | findstr "Version"

set CMAKE=C:\tools\cmake-3.30.2-windows-x86_64\bin\cmake.exe
set SRC=C:\Users\labuser\Documents\HeapExplorer
set BLD=%SRC%\build

echo [*] Configuring with CMake...
"%CMAKE%" -S "%SRC%" -B "%BLD%" -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 (
    echo [!] CMake configure failed
    exit /b 1
)

echo [*] Building...
"%CMAKE%" --build "%BLD%" -- /NOLOGO
if errorlevel 1 (
    echo [!] Build failed
    exit /b 1
)

echo [+] Build complete!
dir /b "%BLD%\bin\*"
