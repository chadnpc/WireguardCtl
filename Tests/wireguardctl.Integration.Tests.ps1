$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$here\..\wireguardctl.psd1" -Force

Describe "Integration tests: wireguardctl" {
  Context "Configuration Generation" {
    It "Generates expected Installer script layout" {
      $dummyKey = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('this_is_32_bytes_of_data_exactly!!'))
      $config = [WgInstallerConfig]::new('wg2', '10.0.0.5/32', '1.1.1.1', $dummyKey, '0.0.0.0/0', 'localhost:51820', 25)
      
      $script = $config.ToInstallerScript()
      
      $script | Should -Match '\$InterfaceName = "wg2"'
      $script | Should -Match '\$ClientIP = "10.0.0.5/32"'
      $script | Should -Match "\$PeerPublicKey = `"$dummyKey`""
      $script | Should -Match '\$Endpoint = "localhost:51820"'
      $script | Should -Match '\$KeepAlive = 25'
    }
  }
  
  Context "Cmdlet Invoke-WireguardCtl mapping" {
    It "Exposes the wgctl alias" {
      $alias = Get-Alias wgctl -ErrorAction SilentlyContinue
      $alias | Should -Not -BeNullOrEmpty
      $alias.ResolvedCommandName | Should -Be 'Invoke-WireguardCtl'
    }
    
    It "Validates parameter mapping structure natively" {
      $cmd = Get-Command Invoke-WireguardCtl
      
      $cmd.Parameters.ContainsKey('ServerPublicKey') | Should -Be $true
      $cmd.Parameters.ContainsKey('Watch') | Should -Be $true
      $cmd.Parameters.ContainsKey('Interactive') | Should -Be $true
    }
    
    It "Has correct Pipeline parameter sets mapped" {
      $cmd = Get-Command Invoke-WireguardCtl
      $sets = $cmd.ParameterSets | Select-Object -ExpandProperty Name
      
      $sets -contains 'Raw' | Should -Be $true
      $sets -contains 'Custom' | Should -Be $true
      $sets -contains 'NetworkConfig' | Should -Be $true
      $sets -contains 'Watch' | Should -Be $true
    }
  }
}
