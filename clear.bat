@echo off
echo Limpando arquivos de log, arquivos temp, caches e lixo do computador...

:: Limpeza de arquivos de log e temporarios do sistema
del *.log /a /s /q /f
del /s /f /q C:\Windows\Temp\*.*
del /s /f /q C:\Windows\Prefetch\*.*
del /s /f /q %temp%\*.*
del /s /f /q C:\Windows\Logs\*.*
del /s /f /q C:\Windows\Minidump\*.*

:: Limpeza de caches de navegadores (Chrome, Firefox, Edge)
del /s /f /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\*.*"
del /s /f /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Media Cache\*.*"
del /s /f /q "%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2\*.*"
del /s /f /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\*.*"
del /s /f /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Media Cache\*.*"

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
@echo off

echo Limpeza concluida.
exit /0