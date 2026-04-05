![banner](https://www.wireguard.com/img/wireguard.svg)

---

🔥 PowerShell module for easy WireGuard management inside your terminal.

`WireguardCtl` simplifies configuring clients, createing automatic Windows installer scripts, managing tunnels, and a watchdog to monitor seamless connectivity.

[![Downloads](https://img.shields.io/powershellgallery/dt/wireguardctl.svg?style=flat&logo=powershell&color=blue)](https://www.powershellgallery.com/packages/wireguardctl)

## Installation

```PowerShell
Install-Module wireguardctl -Scope CurrentUser
Import-Module wireguardctl
```

## Quick Start

The exposed cmdlet `Invoke-WireguardCtl` (alias `wgctl`) supports mapping parameters or using raw argument strings for maximum flexibility.

### 1. Interactive Setup

```powershell
wgctl -Interactive
# same as:
wgctl
```

### 2. Custom Params

Skip the prompts by providing Network details:
```powershell
wgctl -serverPublicKey "x+YourServerPublicKeyHere=" -endpoint "vpn.example.com:51820" -clientIP "10.0.0.5/24" -output "C:\vpn-setup.ps1"
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

## Direct

If you prefer using it in your scripts, import the module and use the exposed classes seamlessly:

### .EXAMPLE
```powershell
#Requires -Modules wireguardctl

# Pass whole string arguments straight to the class
[WireguardCtl]::InstallWireGuard("--interactive --output installer.ps1")

# Use a config payload:
[WireguardCtl]::InstallWireGuard("--config C:\payload.json")
```

### .EXAMPLE
```powershell
# Generate an Installer Programmatically:
$myConfig = [WgInstallerConfig]::new(
    "wg1",                   # Interface Name
    "192.168.10.2/32",       # Client IP
    "1.1.1.1",               # DNS
    "<Base64PubKey>",        # Server Public Key
    "0.0.0.0/0",             # Allowed IPs
    "home.domain.com:51820", # Endpoint
    25                       # KeepAlive
)

$installerScript = $myConfig.ToInstallerScript()
Set-Content -Path "C:\deploy-wg.ps1" -Value $installerScript
```

## License

This project is licensed under the [WTFPL License](LICENSE).
