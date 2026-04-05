$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$here\..\wireguardctl.psd1" -Force

Describe "Feature tests: wireguardctl" {
  Context "WgInstallerValidator" {
    It "Validates valid IPv4 addresses" {
      [WgInstallerValidator]::IsValidIPv4('10.0.0.1/24') | Should -Be $true
      [WgInstallerValidator]::IsValidIPv4('192.168.1.10') | Should -Be $true
    }
    It "Rejects invalid IPv4 addresses" {
      [WgInstallerValidator]::IsValidIPv4('invalid') | Should -Be $false
      [WgInstallerValidator]::IsValidIPv4('10.0.0.256/24') | Should -Be $false
      [WgInstallerValidator]::IsValidIPv4('192.168.1.1/33') | Should -Be $false
    }
    It "Validates Server Public Key" {
      $key = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('this_is_32_bytes_of_data_exactly!!'))
      [WgInstallerValidator]::IsValidPublicKey($key) | Should -Be $true
    }
    It "Rejects invalid Server Public Key" {
      [WgInstallerValidator]::IsValidPublicKey('short_key') | Should -Be $false
    }
    It "Validates Endpoint" {
      [WgInstallerValidator]::IsValidEndpoint('vpn.example.com:51820') | Should -Be $true
      [WgInstallerValidator]::IsValidEndpoint('192.168.1.1:1234') | Should -Be $true
    }
    It "Rejects invalid Endpoint" {
      [WgInstallerValidator]::IsValidEndpoint('vpn.example.com') | Should -Be $false
      [WgInstallerValidator]::IsValidEndpoint('vpn.example.com:0') | Should -Be $false
    }
  }

  Context "WgInstallerConfig" {
    It "Instantiates with defaults" {
      $config = [WgInstallerConfig]::new()
      $config.InterfaceName | Should -Be 'wg0'
      $config.KeepAlive | Should -Be 15
    }
    It "Parses to JSON and back" {
      $config = [WgInstallerConfig]::new()
      $config.DNS = '1.1.1.1'
      $json = $config.ToJson()
      $restored = [WgInstallerConfig]::FromJson($json)
      $restored.DNS | Should -Be '1.1.1.1'
      $restored.InterfaceName | Should -Be 'wg0'
    }
  }
}
