@rem 参数0: exe
@rem 参数1: 输入bin文件 ,原始文件或者压缩档文件
@rem 参数2: 输出文件(目标生成文件）
@rem 参数3: 输入文件类型,0是image文件，1是FLASHBOOT文件 2是secboot文件
@rem 参数4: 是否压缩文件：0：plain文件，1：压缩类型文件
@rem 参数5: 版本号文件
@rem 参数6：升级文件再FLASH里的存放位置（相对位置）
@rem 参数7：升级后的文件启动位置（相对位置）
@rem 参数8：原始bin文件

@echo off

set BINPATH=%1\..\..\..\bin
set TOOLSPATH=%1\..\..

copy %1\Release\List\w60x.map %BINPATH%\WM_W600.map
copy %1\Release\Exe\WM_W600.bin %BINPATH%\WM_W600.bin

copy %BINPATH%\version.txt %BINPATH%\version_bk.txt

%TOOLSPATH%\wm_gzip.exe "%BINPATH%\WM_W600.bin"
%TOOLSPATH%\makeimg.exe "%BINPATH%\WM_W600.bin" "%BINPATH%\WM_W600.img" 0 0 "%BINPATH%\version.txt" 90000 10100
%TOOLSPATH%\makeimg.exe "%BINPATH%\WM_W600.bin.gz" "%BINPATH%\WM_W600_GZ.img" 0 1 "%BINPATH%\version.txt" 90000 10100 "%BINPATH%\WM_W600.bin" 
%TOOLSPATH%\makeimg.exe "%BINPATH%\WM_W600.bin" "%BINPATH%\WM_W600_SEC.img" 0 0 "%BINPATH%\version.txt" 90000 10100
%TOOLSPATH%\makeimg_all.exe "%BINPATH%\secboot.img" "%BINPATH%\WM_W600.img" "%BINPATH%\WM_W600.FLS"
@del "%BINPATH%\WM_W600.img"