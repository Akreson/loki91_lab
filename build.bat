cls

@echo off

set CommonCompilerFlags=-Od -nologo /fp:fast -Oi -W4 -FC -Z7
set CommonLinkerFlags= -incremental:no
REM user32.lib gdi32.lib winmm.lib opengl32.lib

IF NOT EXIST ..\build mkdir ..\build
pushd ..\build

REM 64-bit build
REM Optimization switches /O2
cl %CommonCompilerFlags% ..\code\loki.cpp /link %CommonLinkerFlags%
popd
