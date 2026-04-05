#!/usr/bin/env pwsh
using namespace System.IO
using namespace System.Collections.Concurrent

using module Private\WgInStallerGenerator.psm1

#Requires -PSEdition Core
#Requires -Modules PsModuleBase, argparser, Sixel
#region    Classes

# Main class
# .EXAMPLE
# [WireguardCtl]::InstallWireGuard()
class WireguardCtl : PsModuleBase {

  WireguardCtl() {
  }
  static [String] ShowBanner() {
    $modr = [WireguardCtl]::GetModuleRoot()
    $bpng = [IO.Path]::Combine($modr, 'Private', 'wgbanner.png')
    return (Sixel\ConvertTo-Sixel $bpng)
  }
  static [string] GetModuleRoot() {
    $r = (Get-Module wireguardctl -ListAvailable).ModuleBase
    $r = [string]::IsNullOrWhiteSpace($r) ? (Get-Variable -ValueOnly PSScriptRoot) : $r
    if (![IO.Directory]::Exists($r)) {
      throw [DirectoryNotFoundException]::new("ModulePath $r NOT_FOUND")
    }
    return $r
  }

  static [void] Watch() {
    [WireguardCtl]::Watch('wg0')
  }
  static [void] Watch([string]$TunnelName) {
    if ([string]::IsNullOrWhiteSpace($TunnelName)) {
      $TunnelName = 'wg0' # defaultname
    }
    $svcName = "WireguardTunnel`$$TunnelName"

    $getRx = {
      try {
        $output = & wg show $TunnelName transfer 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($output)) { return $null }
        $parts = $output -split '\s+'
        if ($parts.Count -ge 2) { return [long]$parts[1] }
      } catch {
        Write-Verbose "Error executing wg show: $_"
      }
      return $null
    }

    $recv1 = $null
    while ($null -eq $recv1) {
      $svc = $null
      try {
        $svc = [System.ServiceProcess.ServiceController]::new($svcName)
        $null = $svc.Status
      } catch {
        $svc = $null
      }

      if ($null -eq $svc) {
        $confPath = [System.IO.Path]::Combine($env:ProgramFiles, 'WireGuard', 'Data', 'Configurations', "$TunnelName.conf.dpapi")
        if ([System.IO.File]::Exists($confPath)) {
          & wireguard /installtunnelservice $confPath
          Start-Sleep -Seconds 8
        } else {
          Write-Warning "Wireguard config not found at $confPath. Exiting."
          return
        }
      } elseif ($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        try {
          $svc.Start()
          $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [System.TimeSpan]::FromSeconds(10))
        } catch {
          Write-Warning "Failed to start service $svcName : $_"
        }
      }

      $recv1 = & $getRx
      if ($null -eq $recv1) {
        Start-Sleep -Seconds 2
      }
    }
    Start-Sleep -Seconds 200

    $recv2 = & $getRx
    if ($recv1 -eq $recv2) {
      $doRestart = $true
      while ($doRestart) {
        try {
          $svc = [System.ServiceProcess.ServiceController]::new($svcName)
          if ($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            $svc.Stop()
            $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [System.TimeSpan]::FromSeconds(15))
          }
          $svc.Start()
          $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [System.TimeSpan]::FromSeconds(15))
          $doRestart = $false
        } catch {
          $doRestart = $true
          Start-Sleep -Seconds 5
        }
      }
    }
  }
  static [void] InstallWireGuard() {
    [WireguardCtl]::InstallWireGuard("")
  }
  static [void] InstallWireGuard([string]$argsline) {
    Write-Host ([WireguardCtl]::ShowBanner())
    $argslist = if ([string]::IsNullOrWhiteSpace($argsline)) { @() } else { $argsline -split '\s+' }
    $config = [WgInStallerGenerator]::GetConfigFromArgs($argslist)
    if ($null -eq $config) {
      return
    }

    Write-Host "`nProceeding with WireGuard Installation..." -ForegroundColor Cyan

    try {
      [WgInstallerRunner]::CheckAdmin()
    } catch {
      Write-Error $_.Exception.Message
      return
    }

    if ([WgInstallerRunner]::CheckWireGuardInstalled() -ne 'Installed') {
      [WgInstallerRunner]::SilentInstallWireGuard()
    } else {
      Write-Host "WireGuard is already installed." -ForegroundColor Green
    }

    $paths = [WgInstallerPaths]::new($config.InterfaceName)
    $paths.EnsureDirectories()

    Write-Host "Generating Keys..." -ForegroundColor Yellow
    $keys = [WgInstallerRunner]::GenerateKeys($paths.WgExe)
    $privKey = $keys[0]
    $pubKey = $keys[1]

    $confContent = @"
[Interface]
PrivateKey = $privKey
Address = $($config.ClientIP)
DNS = $($config.DNS)

[Peer]
PublicKey = $($config.ServerPublicKey)
AllowedIPs = $($config.AllowedIPs)
Endpoint = $($config.Endpoint)
PersistentKeepalive = $($config.KeepAlive)
"@
    Write-Host "Configuring tunnel: $($config.InterfaceName)" -ForegroundColor Yellow
    [WgInstallerRunner]::WriteConfigFile($paths.WorkConf, $confContent)
    Copy-Item $paths.WorkConf $paths.FinalConf -Force

    Write-Host "Installing and starting tunnel service..." -ForegroundColor Yellow
    [WgInstallerRunner]::ImportTunnel($paths.WireGuardExe, $paths.FinalConf, $config.InterfaceName)

    Write-Host "WireGuard installed and configured successfully!" -ForegroundColor Green
    Write-Host "Client Public Key: $pubKey" -ForegroundColor Magenta
  }
}
#endregion Classes

# Types that will be available to users when they import the module.
$typestoExport = @(
  [WireguardCtl]
)
$TypeAcceleratorsClass = [PsObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
  if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
    $Message = @(
      "Unable to register type accelerator '$($Type.FullName)'"
      'Accelerator already exists.'
    ) -join ' - '
    "TypeAcceleratorAlreadyExists $Message" | Write-Debug
  }
}
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
  $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Remove($Type.FullName)
  }
}.GetNewClosure();

$scripts = @();
$Public = Get-ChildItem "$PSScriptRoot/Public" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += Get-ChildItem "$PSScriptRoot/Private" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += $Public

foreach ($file in $scripts) {
  try {
    if ([string]::IsNullOrWhiteSpace($file.fullname)) { continue }
    . "$($file.fullname)"
  } catch {
    Write-Warning "Failed to import function $($file.BaseName): $_"
    $host.UI.WriteErrorLine($_)
  }
}

$Param = @{
  Function = $Public.BaseName
  Cmdlet   = '*'
  Alias    = '*'
  Verbose  = $false
}
Export-ModuleMember @Param
