# Otimizacao segura para reduzir stutter no Windows 11
# Criado para uso em desktop/gaming. Nao desativa Defender, Windows Update,
# servicos essenciais, HPET, seguranca de memoria ou recursos criticos.
#
# Execute como Administrador.
# Reinicie o Windows ao terminar.

$ErrorActionPreference = "SilentlyContinue"

function Write-Step($msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan
}

# Auto-elevar para Administrador
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Solicitando permissao de Administrador..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Write-Host "==============================================="
Write-Host "  AJUSTE SEGURO DE STUTTER - WINDOWS 11"
Write-Host "==============================================="

# Pasta de backup
$backup = Join-Path $env:USERPROFILE "Desktop\Backup_Stutter_Tweaks"
New-Item -ItemType Directory -Force -Path $backup | Out-Null

Write-Step "Salvando backup das chaves alteradas"
reg export "HKCU\System\GameConfigStore" "$backup\GameConfigStore.reg" /y | Out-Null
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" "$backup\GameDVR.reg" /y | Out-Null
reg export "HKCU\Software\Microsoft\GameBar" "$backup\GameBar.reg" /y | Out-Null
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" "$backup\PowerThrottling.reg" /y | Out-Null

# Salva plano de energia atual
(powercfg /getactivescheme) | Out-File "$backup\PlanoEnergiaAntes.txt" -Encoding utf8

Write-Step "Ativando plano Alto Desempenho"
powercfg /setactive SCHEME_MIN | Out-Null

Write-Step "Ativando Modo de Jogo do Windows"
New-Item -Path "HKCU:\Software\Microsoft\GameBar" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" `
    -Name "AutoGameModeEnabled" -PropertyType DWord -Value 1 -Force | Out-Null

Write-Step "Desativando gravacao/captura em segundo plano do Xbox Game Bar"
New-Item -Path "HKCU:\System\GameConfigStore" -Force | Out-Null
New-ItemProperty -Path "HKCU:\System\GameConfigStore" `
    -Name "GameDVR_Enabled" -PropertyType DWord -Value 0 -Force | Out-Null

New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" `
    -Name "AppCaptureEnabled" -PropertyType DWord -Value 0 -Force | Out-Null

Write-Step "Desativando Power Throttling global"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" `
    -Name "PowerThrottlingOff" -PropertyType DWord -Value 1 -Force | Out-Null

Write-Step "Limpando arquivos temporarios do usuario"
Get-ChildItem "$env:TEMP\*" -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Step "Verificando RTSS"
$rtss = Get-Process RTSS -ErrorAction SilentlyContinue
if ($rtss) {
    Write-Host ""
    Write-Host "ATENCAO: RivaTuner Statistics Server esta aberto." -ForegroundColor Yellow
    Write-Host "Se o perfil GLOBAL estiver com Detection Level = Medium e Framerate limit = 190,"
    Write-Host "o RTSS pode injetar no navegador e causar travamentos/stutter."
    Write-Host ""
    Write-Host "No perfil GLOBAL do RTSS, use:" -ForegroundColor Yellow
    Write-Host "  Application detection level: None"
    Write-Host "  Framerate limit: 0"
    Write-Host "Depois crie um perfil separado para RobloxPlayerBeta.exe com limite 190."
}

Write-Step "Gerando relatorio rapido do sistema"
$report = Join-Path $backup "Relatorio.txt"
"=== RELATORIO ===" | Out-File $report -Encoding utf8
"Data: $(Get-Date)" | Out-File $report -Append
"" | Out-File $report -Append
"Plano de energia:" | Out-File $report -Append
(powercfg /getactivescheme) | Out-File $report -Append
"" | Out-File $report -Append

"Memoria:" | Out-File $report -Append
Get-CimInstance Win32_OperatingSystem |
    Select-Object @{N='RAM Total GB';E={[math]::Round($_.TotalVisibleMemorySize/1MB,2)}},
                  @{N='RAM Livre GB';E={[math]::Round($_.FreePhysicalMemory/1MB,2)}} |
    Format-List | Out-String | Out-File $report -Append

"Discos:" | Out-File $report -Append
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID,
                  @{N='Livre GB';E={[math]::Round($_.FreeSpace/1GB,1)}},
                  @{N='Total GB';E={[math]::Round($_.Size/1GB,1)}} |
    Format-Table -AutoSize | Out-String | Out-File $report -Append

"Processos com maior uso de memoria:" | Out-File $report -Append
Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First 12 Name, Id, @{N='RAM MB';E={[math]::Round($_.WorkingSet64/1MB,0)}} |
    Format-Table -AutoSize | Out-String | Out-File $report -Append

Write-Host ""
Write-Host "==============================================="
Write-Host "CONCLUIDO." -ForegroundColor Green
Write-Host "Reinicie o computador antes de testar."
Write-Host ""
Write-Host "IMPORTANTE PARA O SEU CASO:"
Write-Host "1. RTSS GLOBAL -> Detection Level = None"
Write-Host "2. RTSS GLOBAL -> Framerate limit = 0"
Write-Host "3. Perfil RobloxPlayerBeta.exe -> Detection Level = Medium"
Write-Host "4. Perfil RobloxPlayerBeta.exe -> Framerate limit = 190"
Write-Host "5. AMD Adrenalin -> limitador de FPS global desativado"
Write-Host ""
Write-Host "Backup e relatorio: $backup"
Write-Host "==============================================="
Read-Host "Pressione Enter para fechar"
