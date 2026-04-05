#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Web
using namespace System.Text
using namespace System.Net.Http
using namespace System.Text.RegularExpressions
using namespace System.Collections.Specialized

#Requires -PSEdition Core
#Requires -Modules PsModuleBase, argparser

#region    enums

enum GenerationMode {
  Interactive
  Direct
  ConfigFile
}

enum InstallStatus {
  NotInstalled
  Downloading
  Installing
  Installed
  Failed
}

#endregion

#region    Exceptions

class WgInstallException : Exception {
  WgInstallException() {}
  WgInstallException([string]$message) : base($message) {}
  WgInstallException([string]$message, [Exception]$innerException) : base($message, $innerException) {}
}

class WgValidationException : Exception {
  WgValidationException() {}
  WgValidationException([string]$message) : base($message) {}
  WgValidationException([string]$message, [Exception]$innerException) : base($message, $innerException) {}
}

#endregion

#region    WgInstallerValidator

class WgInstallerValidator {
  static [bool] IsValidIPv4([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($ip)) { return $false }
    $clean = $ip.Split('/')[0]
    $cidr = $null
    if ($ip.Contains('/')) {
      $parts = $ip.Split('/')
      if ($parts.Length -ne 2) { return $false }
      if (![int]::TryParse($parts[1], [ref]$cidr)) { return $false }
      if ($cidr -lt 0 -or $cidr -gt 32) { return $false }
    }
    return [IPAddress]::TryParse($clean, [ref]$null)
  }

  static [bool] IsValidDNS([string]$dns) {
    if ([string]::IsNullOrWhiteSpace($dns)) { return $false }
    $servers = $dns.Split(',').ForEach({ $_.Trim() })
    foreach ($server in $servers) {
      if (![IPAddress]::TryParse($server, [ref]$null)) {
        if (![Uri]::CheckHostName($server)) { return $false }
      }
    }
    return $true
  }

  static [bool] IsValidPublicKey([string]$key) {
    if ([string]::IsNullOrWhiteSpace($key)) { return $false }
    $key = $key.Trim()
    if ($key.Length -ne 44) { return $false }
    try {
      [Convert]::FromBase64String($key) | Out-Null
      return $true
    } catch {
      return $false
    }
  }

  static [bool] IsValidEndpoint([string]$endpoint) {
    if ([string]::IsNullOrWhiteSpace($endpoint)) { return $false }
    $endpoint = $endpoint.Trim()
    if ($endpoint -notmatch '^.+:\d+$') { return $false }
    $port = [int]($endpoint.Split(':')[-1])
    return $port -gt 0 -and $port -le 65535
  }

  static [bool] IsValidKeepAlive([string]$keepalive) {
    if ([string]::IsNullOrWhiteSpace($keepalive)) { return $false }
    $val = 0
    if (![int]::TryParse($keepalive.Trim(), [ref]$val)) { return $false }
    return $val -ge 0 -and $val -le 65535
  }

  static [void] ValidateConfig([WgInstallerConfig]$config) {
    $errors = [Ordered]@{}
    if (![WgInstallerValidator]::IsValidInterfaceName($config.InterfaceName)) {
      $errors['InterfaceName'] = 'Invalid interface name. Use alphanumeric characters and hyphens only.'
    }
    if (![WgInstallerValidator]::IsValidIPv4($config.ClientIP)) {
      $errors['ClientIP'] = 'Invalid IPv4 address. Use format like 10.0.0.2/24'
    }
    if (![WgInstallerValidator]::IsValidDNS($config.DNS)) {
      $errors['DNS'] = 'Invalid DNS. Use comma-separated IPs or hostnames.'
    }
    if (![WgInstallerValidator]::IsValidPublicKey($config.ServerPublicKey)) {
      $errors['ServerPublicKey'] = 'Invalid public key. Must be 44-character base64 string.'
    }
    if (![WgInstallerValidator]::IsValidIPv4OrWildcard($config.AllowedIPs)) {
      $errors['AllowedIPs'] = 'Invalid AllowedIPs. Use comma-separated CIDRs or 0.0.0.0/0'
    }
    if (![WgInstallerValidator]::IsValidEndpoint($config.Endpoint)) {
      $errors['Endpoint'] = 'Invalid endpoint. Use format host:port'
    }
    if (![WgInstallerValidator]::IsValidKeepAlive([string]$config.KeepAlive)) {
      $errors['KeepAlive'] = 'Invalid keepalive. Must be 0-65535.'
    }
    if ($errors.Count -gt 0) {
      $msg = $errors.GetEnumerator().ForEach({ "$($_.Key): $($_.Value)" }) -join "`n"
      throw [WgValidationException]::new("Configuration validation failed:`n$msg")
    }
  }

  static [bool] IsValidInterfaceName([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }
    return $name -match '^[a-zA-Z0-9_-]+$'
  }

  static [bool] IsValidIPv4OrWildcard([string]$ips) {
    if ([string]::IsNullOrWhiteSpace($ips)) { return $false }
    $items = $ips.Split(',').ForEach({ $_.Trim() })
    foreach ($item in $items) {
      if ($item -eq '0.0.0.0/0' -or $item -eq '::/0') { continue }
      if (![WgInstallerValidator]::IsValidIPv4($item)) { return $false }
    }
    return $true
  }
}

#endregion

#region    WgInstallerConfig

class WgInstallerConfig {
  [string]$InterfaceName = 'wg0'
  [string]$ClientIP = '10.0.0.2/24'
  [string]$DNS = '1.1.1.1, 8.8.8.8'
  [string]$ServerPublicKey = ''
  [string]$AllowedIPs = '0.0.0.0/0'
  [string]$Endpoint = ''
  [int]$KeepAlive = 15

  WgInstallerConfig() {}

  WgInstallerConfig([string]$interfaceName, [string]$clientIP, [string]$dns, [string]$serverPublicKey, [string]$allowedIPs, [string]$endpoint, [int]$keepAlive) {
    $this.InterfaceName = $interfaceName
    $this.ClientIP = $clientIP
    $this.DNS = $dns
    $this.ServerPublicKey = $serverPublicKey
    $this.AllowedIPs = $allowedIPs
    $this.Endpoint = $endpoint
    $this.KeepAlive = $keepAlive
  }

  [string] ToString() {
    return @"
=== WireGuard Client Configuration ===
Interface Name : $($this.InterfaceName)
Client IP      : $($this.ClientIP)
DNS            : $($this.DNS)
Server PubKey  : $($this.ServerPublicKey)
Allowed IPs    : $($this.AllowedIPs)
Endpoint       : $($this.Endpoint)
KeepAlive      : $($this.KeepAlive)
======================================
"@
  }

  [string] ToJson() {
    return $this | ConvertTo-Json -Compress
  }

  static [WgInstallerConfig] FromJson([string]$json) {
    $obj = $json | ConvertFrom-Json
    $config = [WgInstallerConfig]::new()
    $config.InterfaceName = $obj.InterfaceName
    $config.ClientIP = $obj.ClientIP
    $config.DNS = $obj.DNS
    $config.ServerPublicKey = $obj.ServerPublicKey
    $config.AllowedIPs = $obj.AllowedIPs
    $config.Endpoint = $obj.Endpoint
    $config.KeepAlive = $obj.KeepAlive
    return $config
  }

  static [WgInstallerConfig] FromFile([string]$path) {
    $json = [File]::ReadAllText($path)
    return [WgInstallerConfig]::FromJson($json)
  }

  [void] SaveToFile([string]$path) {
    $dir = [Path]::GetDirectoryName($path)
    if (![string]::IsNullOrWhiteSpace($dir) -and !(Test-Path $dir)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $utf8NoBom = [UTF8Encoding]::new($false)
    [File]::WriteAllText($path, $this.ToJson(), $utf8NoBom)
  }

  [string] ToInstallerScript() {
    $script = @'
# ==========================================================
# WireGuard - Client Installer (Windows)
# Auto-generated by WgInStallerGenerator
# ==========================================================

#Requires -RunAsAdministrator

# ---------------- VARIABLES ----------------
$InterfaceName = "{{INTERFACE_NAME}}"
$ClientIP = "{{CLIENT_IP}}"
$DNS = "{{DNS}}"

$PeerPublicKey = "{{SERVER_PUBLIC_KEY}}"
$AllowedIPs = "{{ALLOWED_IPS}}"
$Endpoint = "{{ENDPOINT}}"
$KeepAlive = {{KEEPALIVE}}

# ---------------- PATHS ----------------
$WGBase = [IO.Path]::Combine($env:ProgramFiles, 'WireGuard')
$WGExe = "$WGBase\wireguard.exe"
$WGCmd = "$WGBase\wg.exe"

$WorkDir = "C:\ConfWireGuard"
$WGConfDir = "$WGBase\Data\Configurations"

$WorkConf = "$WorkDir\$InterfaceName.conf"
$FinalConf = "$WGConfDir\$InterfaceName.conf"

# ---------------- ADMIN ----------------
$principal = New-Object Security.Principal.WindowsPrincipal(
  [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run as Administrator." -ForegroundColor Red
  exit 1
}

# ---------------- FUNCTION ----------------
function Write-FileNoBOM {
  param ($Path, $Content)
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

# ---------------- DIRECTORIES ----------------
foreach ($dir in @($WorkDir, $WGConfDir)) {
  if (!(Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir | Out-Null
  }
}

# ---------------- INSTALL WG ----------------
if (!(Test-Path $WGExe)) {
  Write-Host "Installing WireGuard..." -ForegroundColor Yellow
  $Installer = "$env:TEMP\wireguard-installer.exe"

  Invoke-WebRequest `
    -Uri "https://download.wireguard.com/windows-client/wireguard-installer.exe" `
    -OutFile $Installer

  Start-Process $Installer -ArgumentList "/install /quiet" -Wait
  Start-Sleep -Seconds 5
}

# ---------------- KEYS ----------------
$PrivateKey = & $WGCmd genkey
$PublicKey = $PrivateKey | & $WGCmd pubkey

# ---------------- CONF ----------------
$Config = @"
[Interface]
PrivateKey = $PrivateKey
Address = $ClientIP
DNS = $DNS

[Peer]
PublicKey = $PeerPublicKey
AllowedIPs = $AllowedIPs
Endpoint = $Endpoint
PersistentKeepalive = $KeepAlive
"@

Write-FileNoBOM $WorkConf $Config
Copy-Item $WorkConf $FinalConf -Force

# ---------------- IMPORT ----------------
& $WGExe /uninstalltunnelservice $InterfaceName 2>$null
& $WGExe /installtunnelservice $FinalConf

Write-Host "WireGuard installed successfully!" -ForegroundColor Green
Write-Host "Client Public Key: $PublicKey"
'@

    $script = $script -replace '{{INTERFACE_NAME}}', [Regex]::Escape($this.InterfaceName)
    $script = $script -replace '{{CLIENT_IP}}', [Regex]::Escape($this.ClientIP)
    $script = $script -replace '{{DNS}}', [Regex]::Escape($this.DNS)
    $script = $script -replace '{{SERVER_PUBLIC_KEY}}', [Regex]::Escape($this.ServerPublicKey)
    $script = $script -replace '{{ALLOWED_IPS}}', [Regex]::Escape($this.AllowedIPs)
    $script = $script -replace '{{ENDPOINT}}', [Regex]::Escape($this.Endpoint)
    $script = $script -replace '\{\{KEEPALIVE\}\}', $this.KeepAlive

    return $script
  }
}

#endregion

#region    WgInstallerPaths

class WgInstallerPaths {
  [string]$WireGuardBase = [IO.Path]::Combine($env:ProgramFiles, 'WireGuard')
  [string]$WireGuardExe
  [string]$WgExe
  [string]$WorkDir = 'C:\ConfWireGuard'
  [string]$WgConfigDir
  [string]$WorkConf
  [string]$FinalConf

  WgInstallerPaths([string]$interfaceName) {
    $this.WireGuardExe = Join-Path $this.WireGuardBase 'wireguard.exe'
    $this.WgExe = Join-Path $this.WireGuardBase 'wg.exe'
    $this.WgConfigDir = Join-Path $this.WireGuardBase 'Data\Configurations'
    $this.WorkConf = Join-Path $this.WorkDir "$interfaceName.conf"
    $this.FinalConf = Join-Path $this.WgConfigDir "$interfaceName.conf"
  }

  [void] EnsureDirectories() {
    foreach ($dir in @($this.WorkDir, $this.WgConfigDir)) {
      if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
      }
    }
  }
}

#endregion

#region    WgInstallerRunner

class WgInstallerRunner {
  static [void] CheckAdmin() {
    $principal = [Security.Principal.WindowsPrincipal]::new(
      [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      throw [WgInstallException]::new('This operation requires Administrator privileges.')
    }
  }

  static [InstallStatus] CheckWireGuardInstalled() {
    $wgExe = [IO.Path]::Combine($env:ProgramFiles, 'WireGuard', 'wireguard.exe')
    if (Test-Path $wgExe -PathType Leaf -ea Ignore) {
      return 'Installed'
    }
    return 'NotInstalled'
  }

  static [void] SilentInstallWireGuard() {
    $installer = Join-Path $env:TEMP 'wireguard-installer.exe'
    Write-Host 'Downloading WireGuard installer...' -ForegroundColor Yellow
    Invoke-WebRequest `
      -Uri 'https://download.wireguard.com/windows-client/wireguard-installer.exe' `
      -OutFile $installer
    Write-Host 'Installing WireGuard silently...' -ForegroundColor Yellow
    Start-Process $installer -ArgumentList '/install /quiet' -Wait
    Start-Sleep -Seconds 5
    if ([WgInstallerRunner]::CheckWireGuardInstalled() -ne [InstallStatus]::Installed) {
      throw [WgInstallException]::new('WireGuard installation failed.')
    }
  }

  static [string[]] GenerateKeys([string]$wgCmdPath) {
    if (!(Test-Path $wgCmdPath)) {
      throw [WgInstallException]::new("wg.exe not found at $wgCmdPath")
    }
    $privateKey = & $wgCmdPath genkey
    $publicKey = $privateKey | & $wgCmdPath pubkey
    return @($privateKey, $publicKey)
  }

  static [void] WriteConfigFile([string]$path, [string]$content) {
    $dir = [Path]::GetDirectoryName($path)
    if (!(Test-Path $dir)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $utf8NoBom = [UTF8Encoding]::new($false)
    [File]::WriteAllText($path, $content, $utf8NoBom)
  }

  static [void] ImportTunnel([string]$wgExePath, [string]$configPath, [string]$interfaceName) {
    if (!(Test-Path $wgExePath)) {
      throw [WgInstallException]::new("wireguard.exe not found at $wgExePath")
    }
    & $wgExePath /uninstalltunnelservice $interfaceName 2>$null
    & $wgExePath /installtunnelservice $configPath
  }
}

#endregion

#region    WgInStallerGenerator
class WgInStallerGenerator : PsModuleBase {
  <#
  .SYNOPSIS
   A Hlper class to interactively help the user
   Generate a windows installer ps1 script to silently install and configure WireGuard vpn

  .EXAMPLE
  # Interactive mode
  [WgInStallerGenerator]::Generate('--output installer.ps1')

  .EXAMPLE
  # Use config file
  [WgInStallerGenerator]::Generate('--config wg-config.json --output installer.ps1')

  .EXAMPLE
  # Save config after interactive generation
  [WgInStallerGenerator]::Generate('--output installer.ps1 --save-config wg-config.json')
  #>
  static [WgInstallerConfig] GetDefaultConfig() {
    return [WgInstallerConfig]::new()
  }
  static [string] GetDefaultConfigPath() {
    return [IO.Path]::Combine($env:USERPROFILE, '.wg-installer-config.json')
  }

  static [IO.FileInfo] Generate([string]$argline) {
    if ([string]::IsNullOrWhiteSpace($argline)) {
      throw [ArgumentNullException]::new()
    }
    return [WgInStallerGenerator]::Generate($argline.Split(' '))
  }

  static [WgInstallerConfig] GetConfigFromArgs([string[]]$argslist) {
    $schema = @{
      help        = [switch], $false
      h           = [switch], $false
      interactive = [switch], $false
      i           = [switch], $false
      config      = [string], $null
      c           = [string], $null
      output      = [string], $null
      o           = [string], $null
      saveConfig  = [string], $null
    }
    if ($null -eq $argslist -or $argslist.Count -eq 0) {
      return [WgInStallerGenerator]::PromptInteractive()
    }

    $parsed = ArgParser\ConvertTo-Params $argslist -schema $schema

    $showHelp = [bool]($parsed['help'].Value -or $parsed['h'].Value)
    if ($showHelp) {
      [WgInStallerGenerator]::ShowHelp()
      return $null
    }

    $configPath = if ($parsed['config'].Value) { $parsed['config'].Value } elseif ($parsed['c'].Value) { $parsed['c'].Value } else { $null }

    $config = $null
    if ($parsed['interactive'].Value -or $parsed['i'].Value) {
      $config = [WgInStallerGenerator]::PromptInteractive()
    } elseif (![string]::IsNullOrWhiteSpace($configPath)) {
      $config = [WgInStallerGenerator]::LoadFromConfigFile($configPath)
    } elseif ([IO.File]::Exists([WgInStallerGenerator]::GetDefaultConfigPath())) {
      $config = [WgInStallerGenerator]::LoadFromConfigFile([WgInStallerGenerator]::GetDefaultConfigPath())
    } else {
      $config = [WgInStallerGenerator]::PromptInteractive()
    }

    $saveConfigPath = $parsed['saveConfig'].Value
    if (![string]::IsNullOrWhiteSpace($saveConfigPath) -and $null -ne $config) {
      [WgInStallerGenerator]::SaveConfig($config, $saveConfigPath)
    }

    return $config
  }

  static [IO.FileInfo] Generate([string[]]$argslist) {
    $config = [WgInStallerGenerator]::GetConfigFromArgs($argslist)
    if ($null -eq $config) {
      return $null
    }

    $schema = @{
      help        = [switch], $false
      h           = [switch], $false
      interactive = [switch], $false
      i           = [switch], $false
      config      = [string], $null
      c           = [string], $null
      output      = [string], $null
      o           = [string], $null
      saveConfig  = [string], $null
    }
    $parsed = ArgParser\ConvertTo-Params $argslist -schema $schema

    $outputPath = if ($parsed['output'].Value) { $parsed['output'].Value } elseif ($parsed['o'].Value) { $parsed['o'].Value } else { $null }
    if ([string]::IsNullOrWhiteSpace($outputPath)) {
      $outputPath = Join-Path (Get-Location).Path 'installer.ps1'
    }

    return [WgInStallerGenerator]::Generate([WgInstallerConfig]$config, $outputPath)
  }

  static [IO.FileInfo] Generate([DirectoryInfo]$outputPath) {
    $config = [WgInStallerGenerator]::PromptInteractive()
    return [WgInStallerGenerator]::Generate($config, $outputPath.FullName)
  }

  static [IO.FileInfo] Generate([WgInstallerConfig]$config, [string]$outputPath) {
    [WgInstallerValidator]::ValidateConfig($config)
    $scriptContent = $config.ToInstallerScript()
    $dir = [Path]::GetDirectoryName($outputPath)
    if (![string]::IsNullOrWhiteSpace($dir) -and !(Test-Path $dir -PathType Container -ea Ignore)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $utf8NoBom = [UTF8Encoding]::new($false)
    [File]::WriteAllText($outputPath, $scriptContent, $utf8NoBom)
    return [IO.FileInfo]::new($outputPath)
  }

  static [WgInstallerConfig] PromptInteractive() {
    Write-Host "`n=== WireGuard Client Installer ===" -ForegroundColor Cyan
    Write-Host "Enter configuration values (press Enter for defaults)`n" -ForegroundColor DarkCyan

    $config = [WgInstallerConfig]::new()

    $config.InterfaceName = [WgInStallerGenerator]::ReadInput('Interface Name', $config.InterfaceName, {
        param($val) return [WgInstallerValidator]::IsValidInterfaceName($val)
      }, 'Use alphanumeric characters and hyphens only.')

    $config.ClientIP = [WgInStallerGenerator]::ReadInput('Client IP (with CIDR)', $config.ClientIP, {
        param($val) return [WgInstallerValidator]::IsValidIPv4($val)
      }, 'Example: 10.0.0.2/24')

    $config.DNS = [WgInStallerGenerator]::ReadInput('DNS servers (comma-separated)', $config.DNS, {
        param($val) return [WgInstallerValidator]::IsValidDNS($val)
      }, 'Example: 1.1.1.1, 8.8.8.8')

    $config.ServerPublicKey = [WgInStallerGenerator]::ReadInput('Server Public Key', '', {
        param($val) return [WgInstallerValidator]::IsValidPublicKey($val)
      }, '44-character base64 string')

    $config.AllowedIPs = [WgInStallerGenerator]::ReadInput('Allowed IPs', $config.AllowedIPs, {
        param($val) return [WgInstallerValidator]::IsValidIPv4OrWildcard($val)
      }, 'Example: 0.0.0.0/0 or 10.0.0.0/8,192.168.1.0/24')

    $config.Endpoint = [WgInStallerGenerator]::ReadInput('Endpoint (host:port)', '', {
        param($val) return [WgInstallerValidator]::IsValidEndpoint($val)
      }, 'Example: vpn.example.com:51820')

    $keepAliveStr = [WgInStallerGenerator]::ReadInput('Persistent Keepalive (seconds)', [string]$config.KeepAlive, {
        param($val) return [WgInstallerValidator]::IsValidKeepAlive($val)
      }, '0-65535 (15 recommended)')
    $config.KeepAlive = [int]$keepAliveStr

    Write-Host "`n$config" -ForegroundColor Green

    $confirm = Read-Host 'Save this installer script? (Y/n)'
    if ($confirm -match '^[nN]') {
      throw [WgInstallException]::new('Generation cancelled by user.')
    }
    return $config
  }

  static [string] ReadInput([string]$prompt, [string]$default, [scriptblock]$validator, [string]$helpText) {
    $usrinput = [string]::Empty
    while ($true) {
      $displayDefault = if (![string]::IsNullOrWhiteSpace($default)) { " [$default]" } else { '' }
      $value = Read-Host "$prompt$displayDefault"
      if ([string]::IsNullOrWhiteSpace($value)) {
        if (![string]::IsNullOrWhiteSpace($default)) {
          $usrinput = $default
          break
        }
        Write-Host "  This field is required. $helpText" -ForegroundColor Red
        continue
      }
      if ($validator.InvokeReturnAsIs($value)) {
        $usrinput = $value.Trim()
        break
      }
      Write-Host "  Invalid input. $helpText" -ForegroundColor Red
    }
    return $usrinput
  }

  static [WgInstallerConfig] LoadFromConfigFile([string]$path) {
    if (![IO.File]::Exists($path)) {
      throw [WgInstallException]::new("Config file path not found")
    }
    return [WgInstallerConfig]::FromFile($path)
  }

  static [void] SaveConfig([WgInstallerConfig]$config, [string]$path) {
    $config.SaveToFile($path)
    Write-Host "Configuration saved to $path" -ForegroundColor Green
  }

  static [IO.FileInfo] GenerateFromConfigFile([string]$configPath, [string]$outputPath) {
    $config = [WgInStallerGenerator]::LoadFromConfigFile($configPath)
    return [WgInStallerGenerator]::Generate($config, $outputPath)
  }

  static [void] ShowHelp() {
    $help = @"
WireGuard Client Installer

USAGE:
  Import-Module WireGuardCtl -Scope Local
  [WgInStallerGenerator]::Generate(@('--interactive', '--output', 'installer.ps1'))

OPTIONS:
  --interactive, -i       Interactive mode with prompts (default if no config specified)
  --config <path>, -c     Load configuration from JSON file
  --output <path>, -o     Output path for generated installer script
  --save-config <path>    Save configuration to JSON file after generation
  --help, -h              Show this help message

EXAMPLES:
  # Interactive mode
  [WgInStallerGenerator]::Generate('--output installer.ps1')

  # From config file
  [WgInStallerGenerator]::Generate(@('--config', 'wg-config.json', '--output', 'installer.ps1'))

  # Save config after interactive generation
  [WgInStallerGenerator]::Generate('--output installer.ps1 --save-config wg-config.json')
"@
    Write-Host $help -f Green
  }
}

#endregion

# Types that will be available to users when they import the module.
$typestoExport = @(
  [GenerationMode],
  [InstallStatus],
  [WgInstallException],
  [WgValidationException],
  [WgInstallerValidator],
  [WgInstallerConfig],
  [WgInstallerPaths],
  [WgInstallerRunner],
  [WgInStallerGenerator]
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
