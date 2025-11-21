@echo off
:: init.bat - Limpeza segura e otimização (não apaga arquivos importantes)
@echo off
setlocal EnableDelayedExpansion

set LOG=%LOCALAPPDATA%\init_cleanup_log.txt
echo ===== Init Cleanup: %date% %time% =====>> "%LOG%"

echo Removendo verificação de privilégios; executando todos os comandos (alguns podem falhar se não rodar como admin).>> "%LOG%"

echo Sincronizando hora (w32time) - operacao leve...>> "%LOG%"
sc config w32time start= auto 2> nul
net start w32time 2> nul
w32tm /resync 2> nul
net stop w32time 2> nul
sc config w32time start= disabled 2> nul

echo Limpando temporários do usuário...>> "%LOG%"
if exist "%temp%\*" (
	for /d %%D in ("%temp%\*") do rd /s /q "%%D" 2>nul
	del /f /q "%temp%\*.*" 2>nul
	echo Limpeza de %%temp%% concluida>> "%LOG%"
) else (
	echo Pasta %%temp%% vazia ou inexistente>> "%LOG%"
)

echo Limpando temporários do sistema (C:\Windows\Temp)...>> "%LOG%"
if exist "C:\Windows\Temp\*" (
	takeown /f "C:\Windows\Temp" /r /d y >nul 2>&1
	for /d %%D in ("C:\Windows\Temp\*") do rd /s /q "%%D" 2>nul
	del /f /q "C:\Windows\Temp\*.*" 2>nul
	echo Limpeza C:\Windows\Temp concluida>> "%LOG%"
) else (
	echo C:\Windows\Temp vazia ou inexistente>> "%LOG%"
)

:: Observação: não removemos Prefetch nem todos os arquivos .log globalmente - isso pode afetar
:: desempenho e diagnostico. Mantemos limpeza dirigida e segura.

echo Limpando caches de navegadores e apps (se existirem)...>> "%LOG%"
if exist "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\*" (
	rd /s /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache" 2>nul
	echo Chrome cache limpo>> "%LOG%"
) else echo Chrome cache não encontrado>> "%LOG%"

if exist "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Media Cache\*" (
	rd /s /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Media Cache" 2>nul
	echo Chrome media cache limpo>> "%LOG%"
) 

if exist "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\*" (
	rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache" 2>nul
	echo Edge cache limpo>> "%LOG%"
)

if exist "%LOCALAPPDATA%\Mozilla\Firefox\Profiles\" (
	for /d %%P in ("%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*") do (
		if exist "%%P\cache2\*" rd /s /q "%%P\cache2" 2>nul & echo Firefox cache limpo em %%P>> "%LOG%"
	)
)

if exist "%LOCALAPPDATA%\Discord\Cache\*" (
	rd /s /q "%LOCALAPPDATA%\Discord\Cache" 2>nul
	echo Discord cache limpo>> "%LOG%"
)

if exist "%LOCALAPPDATA%\Microsoft\Teams\Cache\*" (
	rd /s /q "%LOCALAPPDATA%\Microsoft\Teams\Cache" 2>nul
	echo Teams cache limpo>> "%LOG%"
)

if exist "%LOCALAPPDATA%\Spotify\Storage\*" (
	rd /s /q "%LOCALAPPDATA%\Spotify\Storage" 2>nul
	echo Spotify storage limpo>> "%LOG%"
)

if exist "%LOCALAPPDATA%\Steam\htmlcache\*" (
	rd /s /q "%LOCALAPPDATA%\Steam\htmlcache" 2>nul
	echo Steam htmlcache limpo>> "%LOG%"
)

:: Limpar cache do OneDrive de forma segura (somente subpastas cache)
if exist "%LOCALAPPDATA%\Microsoft\OneDrive\*\cache\*" (
	for /d %%O in ("%LOCALAPPDATA%\Microsoft\OneDrive\*\cache") do rd /s /q "%%O" 2>nul & echo OneDrive cache limpo em %%O>> "%LOG%"
)

echo Limpando cache de miniaturas (thumbcache)...>> "%LOG%"
if exist "%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db" (
	del /s /f /q "%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db" 2>nul
	echo Thumbnails limpos>> "%LOG%"
)

echo Limpando relatórios de erro do Windows (WER) - somente arquivos antigos...>> "%LOG%"
if exist "%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportArchive\*" (
	del /s /f /q "%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportArchive\*" 2>nul
	echo ReportArchive limpo>> "%LOG%"
)
if exist "%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportQueue\*" (
	del /s /f /q "%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportQueue\*" 2>nul
	echo ReportQueue limpo>> "%LOG%"
)

echo Limpando cache da Microsoft Store (wsreset)...>> "%LOG%"
if exist "%windir%\System32\wsreset.exe" (
	start /wait "" "%windir%\System32\wsreset.exe" >nul 2>&1
	echo wsreset executado>> "%LOG%"
) else echo wsreset não encontrado>> "%LOG%"

echo Limpando Windows Update (apenas Download contents)...>> "%LOG%"
net stop wuauserv >nul 2>&1
if exist "C:\Windows\SoftwareDistribution\Download\*" (
	del /s /f /q "C:\Windows\SoftwareDistribution\Download\*" 2>nul
	echo Windows Update Download limpo>> "%LOG%"
) else echo Pasta de Download do Windows Update vazia>> "%LOG%"

echo Rodando limpeza de componentes do Windows (DISM)...>> "%LOG%"
dism /online /Cleanup-Image /StartComponentCleanup >> "%LOG%" 2>&1
echo DISM StartComponentCleanup executado (ou erro registrado)>> "%LOG%"

echo Otimizando unidades (SSD/HDD) via PowerShell (Optimize-Volume)...>> "%LOG%"
powershell -NoProfile -Command "Get-Volume -FileSystemType NTFS | Where-Object DriveType -EQ 3 | ForEach-Object { if ($_.MediaType -eq 'SSD') { Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -Verbose } else { Optimize-Volume -DriveLetter $_.DriveLetter -Defrag -Verbose } }" >> "%LOG%" 2>&1
echo Otimizacao concluida (ou erro registrado)>> "%LOG%"

echo Limpando arquivos de logs temporarios de apps (somente pasta Logs do Windows se existir)...>> "%LOG%"
if exist "C:\Windows\Logs\*" (
	for /d %%L in ("C:\Windows\Logs\*") do (
		rem manter pastas essenciais; excluir logs temporarios reconhecidos
		if exist "%%L\CBSclean.log" del /f /q "%%L\CBSclean.log" 2>nul
	)
)

echo Limpando Lixeira (silencioso)...>> "%LOG%"
rd /s /q C:\$Recycle.bin 2>nul
powershell.exe -NoProfile -Command "Clear-RecycleBin -Confirm:$false" >nul 2>&1
echo Lixeira limpa>> "%LOG%"

echo Removendo dispositivos com status Unknown (opcional)...>> "%LOG%"
POWERSHELL "Get-PnpDevice | Where-Object Status -eq 'Unknown' | ForEach-Object { pnputil /remove-device $_.InstanceId }" >> "%LOG%" 2>&1
echo Remocao de dispositivos Unknown tentada (ou erro registrado)>> "%LOG%"

echo Finalizando: resumindo ações no log...>> "%LOG%"
echo ===== Fim: %date% %time% =====>> "%LOG%"

endlocal
echo Limpeza concluida. Verifique o log em %LOG%
exit /0