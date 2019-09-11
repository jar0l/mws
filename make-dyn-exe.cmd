@echo off
setlocal
set res="res\main.res" 
if not exist %res% set res=
g++ main.cpp %res% -l shlwapi -l wininet -L lib -l httpapi -o dmws.exe
pause