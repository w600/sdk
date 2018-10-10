@rem 参数0: exe
@rem 参数1: 输入bin文件 ,原始文件或者压缩档文件
@rem 参数2 :输出文件 
@rem 参数3:  输入文件类型,0是image文件，1是FLASHBOOT文件 2是secboot文件
@rem 参数4: 是否压缩文件：0：plain文件，1：压缩类型文件
@rem 参数5: 版本号文件，执行完exe之后版本号会自动累加
@rem 参数6：存放位置
@rem 参数7：原始bin文件
@rem 参数8：压缩文件的解压位置

@echo off

copy WM_W600.map ..\..\..\Bin
copy objs\WM_W600.bin ..\..\..\Bin
cd ..\..\..\Tools

copy ..\Bin\version.txt ..\Bin\version_bk.txt

makeimg.exe "..\Bin\WM_W600.bin" "..\Bin\WM_W600.img" 0 0 "..\Bin\version.txt" E000
makeimg.exe "..\Bin\WM_W600.bin" "..\Bin\WM_W600_SEC.img" 0 0 "..\Bin\version.txt" 7E800
makeimg_all.exe "..\Bin\secboot.img" "..\Bin\WM_W600.img" "..\Bin\WM_W600.FLS"
@del "..\Bin\WM_W600.img"
copy out.img ..\Bin\WM_W600.FLS



