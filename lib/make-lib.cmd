@echo off
dlltool -d httpapi.def -D httpapi.dll -k -l libhttpapi.a -S as.exe
pause