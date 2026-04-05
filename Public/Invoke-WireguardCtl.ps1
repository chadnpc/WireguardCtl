function Invoke-WireguardCtl {
  [CmdletBinding(DefaultParameterSetName = 'Custom')]
  [Alias('wgctl', 'WireguardCtl')]
  param (
    [Parameter(ParameterSetName = 'Raw', Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$ArgumentList,

    [Parameter(ParameterSetName = 'Custom')]
    [switch]$Interactive,

    [Parameter(ParameterSetName = 'Custom')]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [Parameter(ParameterSetName = 'Custom')]
    [Parameter(ParameterSetName = 'NetworkConfig')]
    [string]$SaveConfig,

    [Parameter(ParameterSetName = 'Custom')]
    [Parameter(ParameterSetName = 'NetworkConfig')]
    [string]$Output,

    [Parameter(ParameterSetName = 'Watch')]
    [switch]$Watch,

    [Parameter(ParameterSetName = 'Watch')]
    [string]$TunnelName = 'wg0',

    [Parameter(ParameterSetName = 'NetworkConfig', Mandatory = $true)]
    [string]$ServerPublicKey,

    [Parameter(ParameterSetName = 'NetworkConfig', Mandatory = $true)]
    [string]$Endpoint,

    [Parameter(ParameterSetName = 'NetworkConfig')]
    [string]$InterfaceName = 'wg0',

    [Parameter(ParameterSetName = 'NetworkConfig')]
    [string]$ClientIP = '10.0.0.2/24',

    [Parameter(ParameterSetName = 'NetworkConfig')]
    [string]$DNS = '1.1.1.1, 8.8.8.8',

    [Parameter(ParameterSetName = 'NetworkConfig')]
    [string]$AllowedIPs = '0.0.0.0/0',

    [Parameter(ParameterSetName = 'NetworkConfig')]
    [int]$KeepAlive = 15
  )

  begin {
  }

  process {
    if ($PSCmdlet.ParameterSetName -eq 'Watch') {
      [WireguardCtl]::Watch($TunnelName)
      return
    }

    if ($PSCmdlet.ParameterSetName -eq 'Raw' -and $ArgumentList.Count -gt 0) {
      $argsString = ($ArgumentList -join ' ')
      [WireguardCtl]::InstallWireGuard($argsString)
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'NetworkConfig') {
      $tempConf = $null
      try {
        $tempConf = [System.IO.Path]::GetTempFileName() + '.json'
        $config = [WgInstallerConfig]::new($InterfaceName, $ClientIP, $DNS, $ServerPublicKey, $AllowedIPs, $Endpoint, $KeepAlive)
        $config.SaveToFile($tempConf)
        
        $argsArray = @("--config `"$tempConf`"")
        if ($SaveConfig) { $argsArray += '--saveConfig'; $argsArray += "`"$SaveConfig`"" }
        if ($Output) { $argsArray += '--output'; $argsArray += "`"$Output`"" }
        
        $argsString = ($argsArray -join ' ')
        [WireguardCtl]::InstallWireGuard($argsString)
      } finally {
        if ($null -ne $tempConf -and (Test-Path $tempConf -ErrorAction SilentlyContinue)) {
          Remove-Item $tempConf -Force -ErrorAction SilentlyContinue
        }
      }
    }
    else {
      # Custom parameter set (mapped to CLI options)
      $argsArray = @()
      if ($Interactive) { $argsArray += '--interactive' }
      if ($ConfigPath) { $argsArray += '--config'; $argsArray += "`"$ConfigPath`"" }
      if ($SaveConfig) { $argsArray += '--saveConfig'; $argsArray += "`"$SaveConfig`"" }
      if ($Output) { $argsArray += '--output'; $argsArray += "`"$Output`"" }

      $argsString = ($argsArray -join ' ')
      [WireguardCtl]::InstallWireGuard($argsString)
    }
  }

  end {
  }
}