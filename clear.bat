@echo off
echo Limpando arquivos de log, arquivos temp, caches e lixo do computador...

:: Limpa a memória RAM
echo Liberando memória RAM...
echo.> %temp%\emptyfile
del %temp%\emptyfile

:: Limpeza de arquivos de log e temporarios do sistema
del *.log /a /s /q /f
del /s /f /q C:\Windows\Temp\*.*
del /s /f /q C:\Windows\Prefetch\*.*
del /s /f /q %temp%\*.*
del /s /f /q C:\Windows\Logs\*.*
del /s /f /q C:\Windows\Minidump\*.*

:: Limpeza de rastros de navegacao (historico, cookies, etc.)
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 16384
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2

:: Limpeza de DNS
ipconfig /flushdns

:: Limpeza de thumbnails (miniaturas)
del /s /f /q "%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db"

:: Limpeza de arquivos de sistema antigos (Windows.old)
if exist C:\Windows.old rd /s /q C:\Windows.old

:: Limpeza de cache do .NET Framework
del /s /f /q "%WINDIR%\Microsoft.NET\Framework\*\Temporary ASP.NET Files\*.*"
del /s /f /q "%WINDIR%\Microsoft.NET\Framework64\*\Temporary ASP.NET Files\*.*"

:: Limpeza de cache do OneDrive
del /s /f /q "%LOCALAPPDATA%\Microsoft\OneDrive\*\cache\*.*"

:: Limpeza de cache do Windows Update
del /s /f /q C:\Windows\SoftwareDistribution\Download\*.*

:: Limpeza de atualizações do Windows
net stop wuauserv
net stop UsoSvc
rd /s /q C:\Windows\SoftwareDistribution
md C:\Windows\SoftwareDistribution

:: Limpeza da pasta Downloads
echo Limpando a pasta Downloads...
del /s /f /q "%USERPROFILE%\Downloads\*.*"
rd /s /q "%USERPROFILE%\Downloads"
md "%USERPROFILE%\Downloads"
echo Pasta Downloads limpa.

:: Limpeza da pasta Imagens
echo Limpando a pasta Imagens...
del /s /f /q "%USERPROFILE%\Pictures\*.*"
rd /s /q "%USERPROFILE%\Pictures"
md "%USERPROFILE%\Pictures"
echo Pasta Imagens limpa.

:: Limpeza de pastas temporárias
RD /S /Q %temp%
MKDIR %temp%
takeown /f "%temp%" /r /d y
RD /S /Q C:\Windows\Temp
MKDIR C:\Windows\Temp
takeown /f "C:\Windows\Temp" /r /d y
takeown /f %temp% /r /d y

:: Limpeza de caches de programas comuns
del /s /f /q "%LOCALAPPDATA%\Discord\Cache\*.*"
del /s /f /q "%LOCALAPPDATA%\Spotify\Storage\*.*"
del /s /f /q "%LOCALAPPDATA%\Steam\htmlcache\*.*"
del /s /f /q "%LOCALAPPDATA%\Microsoft\Teams\Cache\*.*"

:: Limpeza de arquivos antigos do Windows Update
del /s /f /q C:\Windows\SoftwareDistribution\Download\*.*
del /s /f /q C:\Windows\System32\catroot2\*.*

:: Limpeza da Lixeira
echo Limpando a Lixeira...
rd /s /q C:\$Recycle.bin
echo Lixeira limpa.

echo %w% -  Cleaning Useless Device Data...%b%
chcp 437 > nul
@echo on
POWERSHELL "$Devices = Get-PnpDevice | ? Status -eq Unknown;foreach ($Device in $Devices) { &\"pnputil\" /remove-device $Device.InstanceId }"

del %temp%\*.* /s /q
del C:\Windows\temp\*.*/s/q
del C:\Windows\prefetch\*.*/s/q
/s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
deltree /y c:\windows\tempor~1
deltree /y c:\windows\temp
deltree /y c:\windows\tmp
deltree /y c:\windows\ff*.tmp
deltree /y c:\windows\history
deltree /y c:\windows\cookies
deltree /y c:\windows\recent
deltree /y c:\windows\spool\printers
del c:\WIN386.SWP
cls

FOR /F "tokens=1, 2 * " %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin

for /F "tokens=*" %%G in ('wevtutil.exe el') DO (
    echo Limpando logs de eventos: %%G
    wevtutil.exe cl %%G
)

del /s /f /q "%USERPROFILE%\Local Settings\History"\*.*
rd /s /q "%USERPROFILE%\Local Settings\History"
md "%USERPROFILE%\Local Settings\History"

del /s /f /q "%USERPROFILE%\Local Settings\Temporary Internet Files"\*.*
rd /s /q "%USERPROFILE%\Local Settings\Temporary Internet Files"
md "%USERPROFILE%\Local Settings\Temporary Internet Files"

del /s /f /q "%USERPROFILE%\Local Settings\Temp"\*.*
rd /s /q "%USERPROFILE%\Local Settings\Temp"
md "%USERPROFILE%\Local Settings\Temp"

del /s /f /q "%USERPROFILE%\Recent"\*.*
rd /s /q "%USERPROFILE%\Recent"
md "%USERPROFILE%\Recent"

del /s /f /q "%USERPROFILE%\Cookies"\*.*
rd /s /q "%USERPROFILE%\Cookies"
md "%USERPROFILE%\Cookies"

for /f %%a in ('wmic cpu get L2CacheSize ^| findstr /r "[0-9][0-9]"') do (
    set /a l2c=%%a
    set /a sum1=%%a
)

for /f %%a in ('wmic cpu get L3CacheSize ^| findstr /r "[0-9][0-9]"') do (
    set /a l3c=%%a
    set /a sum2=%%a
)

RD /S /Q %temp%
MKDIR %temp%
takeown /f "%temp%" /r /d y
takeown /f "C:\Windows\Temp" /r /d y
RD /S /Q C:\Windows\Temp
MKDIR C:\Windows\Temp
takeown /f "C:\Windows\Temp" /r /d y
takeown /f %temp% /r /d y
takeown /A /R /D Y /F C:\Users\%USERNAME%\AppData\Local\Temp\
icacls C:\Users\%USERNAME%\AppData\Local\Temp\ /grant administradores:F /T /C
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Temp\
md C:\Users\%USERNAME%\AppData\Local\Temp\
takeown /A /R /D Y /F C:\windows\temp
icacls C:\windows\temp /grant administradores:F /T /C
rmdir /q /s c:\windows\temp
md c:\windows\temp
cls

del c:\windows\logs\cbs\*.log
del C:\Windows\Logs\MoSetup\*.log
del C:\Windows\Panther\*.log /s /q
del C:\Windows\inf\*.log /s /q
del C:\Windows\logs\*.log /s /q
del C:\Windows\SoftwareDistribution\*.log /s /q
del C:\Windows\Microsoft.NET\*.log /s /q
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\WebCache\*.log /s /q
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\SettingSync\*.log /s /q
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\Explorer\ThumbCacheToDelete\*.tmp /s /q
del C:\Users\%USERNAME%\AppData\Local\Microsoft\"Terminal Server Client"\Cache\*.bin /s /q
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\INetCache\

rd /s /q C:\Windows\SoftwareDistribution
md C:\Windows\SoftwareDistribution

cd/
del *.log /a /s /q /f
@echo off
echo Limpeza concluida.
exit /0