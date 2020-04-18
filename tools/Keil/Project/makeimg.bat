@rem %1 - arg1, used to indicate the flash layout size, which can be 1M and 2M.
@rem %2 - arg2, used to instruct the firmware to download a serial port, such as COM3. If it is empty, do not use the download function.

@echo off

set TGNAME=wm_w600
set OBNAME=WM_W600

copy "%OBNAME%.map" "..\..\..\Bin\%TGNAME%.map"
copy "objs\%OBNAME%.bin" "..\..\..\Bin\%TGNAME%.bin"
cd "..\..\..\Tools"

if "%1" == "2M" (
set IMGTYPE=2M
set UPDADDR=100000
set RUNADDR=10100
) else (
set IMGTYPE=1M
set UPDADDR=90000
set RUNADDR=10100
)

wm_tool -b "..\Bin\%TGNAME%.bin" -sb "..\Bin\secboot.img" -fc compress -it %IMGTYPE% -ua %UPDADDR% -ra %RUNADDR% -o "..\Bin\%TGNAME%"

if "%2" neq "" (wm_tool -c %2 -ds 2M -dl "..\Bin\%TGNAME%.fls" -eo secboot -ws 115200 -rs at)