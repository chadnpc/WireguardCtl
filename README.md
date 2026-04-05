![banner](https://www.wireguard.com/img/wireguard.svg)

---
🔥 Blazingly fast PowerShell toolset that stonks up your WireGuard management and terminal game.

`WireguardCtl` is a PowerShell module for interacting with WireGuard. 

It simplifies configuring clients, creating automatic Windows installer scripts, managing tunnels, and even comes with a watchdog to ensure seamless connectivity.

[![Downloads](https://img.shields.io/powershellgallery/dt/wireguardctl.svg?style=flat&logo=powershell&color=blue)](https://www.powershellgallery.com/packages/wireguardctl)

## Features
- **Effortless Configuration**: Interactive prompt or fully parameter-driven setup.
- **Tunnel Watchdog**: Monitors network connectivity and recovers failed handshakes.
- **Native PowerShell Classes**: Reusable components (`WgInstallerConfig`, `WgInStallerGenerator`, etc.) inside your own tools.
- **Installer Generation**: Package configurations into standalone scripts for easy distribution.

## Installation

```PowerShell
Install-Module wireguardctl -Scope CurrentUser
Import-Module wireguardctl
```

## Quick Start (Cmdlet Usage: `wgctl`)

The primary cmdlet exposed is `Invoke-WireguardCtl` (alias `wgctl`). It supports mapping parameters or using raw argument strings for maximum flexibility.

### 1. Interactive Setup
Run `wgctl` directly to start the interactive configuration prompt:
```powershell
wgctl -Interactive
# Or simpler:
wgctl
```

### 2. Full Custom Parameters
Skip the prompts by providing Network details natively via PowerShell parameters:
```powershell
wgctl -ServerPublicKey "x+YourServerPublicKeyHere=" `
      -Endpoint "vpn.example.com:51820" `
      -ClientIP "10.0.0.5/24" `
      -Output "C:\vpn-setup.ps1"
```

### 3. Load from Config File
Generate and apply configuration using a pre-saved JSON config:
```powershell
wgctl -ConfigPath "C:\wg-config.json" -SaveConfig "C:\wg-config-backup.json"
```

### 4. Running the Tunnel Watchdog
Need to monitor a specific tunnel (like `wg0`)? Just start the watcher:
```powershell
wgctl -Watch -TunnelName "wg0"
```

## Class Direct Usage (`[WireguardCtl]`)

If you prefer building advanced scripts, import the module and use the exposed classes seamlessly:

### Install WireGuard directly passing argument lines
```powershell
# Passes a string argument straight to the argparser engine
[WireguardCtl]::InstallWireGuard("--interactive --output installer.ps1")

# Use a config payload
[WireguardCtl]::InstallWireGuard("--config C:\payload.json")
```

### Generating an Installer Programmatically
```powershell
$myConfig = [WgInstallerConfig]::new(
    "wg1",               # Interface Name
    "192.168.10.2/32",   # Client IP
    "1.1.1.1",           # DNS
    "<Base64PubKey>",    # Server Public Key
    "0.0.0.0/0",         # Allowed IPs
    "home.domain.com:51820", # Endpoint
    25                   # KeepAlive
)

$installerScript = $myConfig.ToInstallerScript()
Set-Content -Path "C:\deploy-wg.ps1" -Value $installerScript
```

## License

This project is licensed under the [WTFPL License](LICENSE).
