# Atualizador seguro do Windows 11
# Instala as atualizacoes oferecidas pelo Windows Update (incluindo atualizacao
# de recurso/versao quando ela estiver liberada para este computador).
# Nao ignora bloqueios de compatibilidade (safeguard holds) da Microsoft.
#
# Execute como Administrador.
# O script NAO instala drivers opcionais e NAO reinicia sem perguntar.

$ErrorActionPreference = "Stop"

function Write-Step([string]$Text) {
    Write-Host "`n==> $Text" -ForegroundColor Cyan
}

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Solicitando permissao de Administrador..."
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`""
        )
        exit
    }
}

Ensure-Admin

Write-Host "========================================================"
Write-Host "      ATUALIZADOR DO WINDOWS 11 - WINDOWS UPDATE"
Write-Host "========================================================"

# Verifica sistema operacional
$os = Get-CimInstance Win32_OperatingSystem
$caption = $os.Caption
$build = [int]$os.BuildNumber

Write-Host "Sistema atual : $caption"
Write-Host "Build atual   : $build"

if ($caption -notmatch "Windows 11") {
    Write-Host "`nEste script foi preparado para Windows 11." -ForegroundColor Yellow
    $continue = Read-Host "Deseja continuar mesmo assim? (S/N)"
    if ($continue -notmatch '^[SsYy]$') { exit }
}

# Cria pasta de log
$logDir = Join-Path $env:USERPROFILE "Desktop\Windows11_Update_Log"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir ("WindowsUpdate_{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

Start-Transcript -Path $logFile -Force | Out-Null

try {
    Write-Step "Verificando servicos do Windows Update"

    $services = @("wuauserv", "bits", "cryptsvc")
    foreach ($svc in $services) {
        try {
            $s = Get-Service $svc
            if ($s.Status -ne "Running") {
                Start-Service $svc
            }
            Write-Host "$svc : OK"
        } catch {
            Write-Host "$svc : nao foi possivel iniciar ($($_.Exception.Message))" -ForegroundColor Yellow
        }
    }

    Write-Step "Solicitando uma nova deteccao de atualizacoes"
    try {
        $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
        $autoUpdate.DetectNow()
    } catch {
        # A busca abaixo ainda funciona mesmo se DetectNow nao estiver disponivel.
    }

    $rebootNeeded = $false
    $pass = 1
    $maxPasses = 4

    while ($pass -le $maxPasses) {
        Write-Step "Busca $pass de $maxPasses"

        $session = New-Object -ComObject Microsoft.Update.Session
        $session.ClientApplicationID = "Windows 11 Update Script"

        $searcher = $session.CreateUpdateSearcher()

        # Apenas atualizacoes de software; exclui drivers opcionais.
        $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")

        if ($result.Updates.Count -eq 0) {
            Write-Host "Nenhuma atualizacao pendente foi encontrada." -ForegroundColor Green
            break
        }

        $updates = New-Object -ComObject Microsoft.Update.UpdateColl

        Write-Host "`nAtualizacoes encontradas:"
        for ($i = 0; $i -lt $result.Updates.Count; $i++) {
            $u = $result.Updates.Item($i)

            # Ignora atualizacoes que exigem interacao do usuario.
            if ($u.InstallationBehavior.CanRequestUserInput) {
                Write-Host "  [IGNORADA] $($u.Title) - exige interacao manual" -ForegroundColor Yellow
                continue
            }

            if (-not $u.EulaAccepted) {
                try { $u.AcceptEula() } catch {}
            }

            [void]$updates.Add($u)
            Write-Host "  + $($u.Title)"
        }

        if ($updates.Count -eq 0) {
            Write-Host "Nao ha atualizacoes instalaveis automaticamente." -ForegroundColor Yellow
            break
        }

        Write-Step "Baixando $($updates.Count) atualizacao(oes)"
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $updates
        $downloadResult = $downloader.Download()

        Write-Host "Resultado do download: $($downloadResult.ResultCode)"

        # Instala apenas o que foi efetivamente baixado.
        $downloaded = New-Object -ComObject Microsoft.Update.UpdateColl
        for ($i = 0; $i -lt $updates.Count; $i++) {
            if ($updates.Item($i).IsDownloaded) {
                [void]$downloaded.Add($updates.Item($i))
            } else {
                Write-Host "  [NAO BAIXADA] $($updates.Item($i).Title)" -ForegroundColor Yellow
            }
        }

        if ($downloaded.Count -eq 0) {
            Write-Host "Nenhuma atualizacao foi baixada; encerrando esta tentativa." -ForegroundColor Yellow
            break
        }

        Write-Step "Instalando $($downloaded.Count) atualizacao(oes)"
        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $downloaded
        $installResult = $installer.Install()

        Write-Host "Resultado geral da instalacao: $($installResult.ResultCode)"

        for ($i = 0; $i -lt $downloaded.Count; $i++) {
            $itemResult = $installResult.GetUpdateResult($i)
            $title = $downloaded.Item($i).Title
            Write-Host "  [$($itemResult.ResultCode)] $title"
        }

        if ($installResult.RebootRequired) {
            $rebootNeeded = $true
            Write-Host "`nO Windows precisa ser reiniciado para continuar/concluir." -ForegroundColor Yellow
            break
        }

        $pass++
        Start-Sleep -Seconds 5
    }

    Write-Step "Versao apos a instalacao"
    $osAfter = Get-CimInstance Win32_OperatingSystem
    Write-Host "Sistema : $($osAfter.Caption)"
    Write-Host "Build   : $($osAfter.BuildNumber)"

    Write-Host "`nObservacao:" -ForegroundColor Cyan
    Write-Host "O script instala a versao mais recente que o Windows Update oferece para este PC."
    Write-Host "Se uma atualizacao de recurso ainda estiver bloqueada pela Microsoft por compatibilidade,"
    Write-Host "o script nao ignora esse bloqueio."

    if ($rebootNeeded) {
        Write-Host "`nReinicio necessario." -ForegroundColor Yellow
        $answer = Read-Host "Deseja reiniciar o computador agora? (S/N)"
        if ($answer -match '^[SsYy]$') {
            Stop-Transcript | Out-Null
            Restart-Computer -Force
            exit
        }
    } else {
        Write-Host "`nProcesso concluido sem reinicio obrigatorio detectado." -ForegroundColor Green
    }

} catch {
    Write-Host "`nERRO: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Consulte o log em: $logFile" -ForegroundColor Yellow
} finally {
    try { Stop-Transcript | Out-Null } catch {}
}

Write-Host "`nLog salvo em:"
Write-Host $logFile
Read-Host "`nPressione Enter para fechar"
