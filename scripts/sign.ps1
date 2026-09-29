[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Signtool,
    [Parameter(Mandatory)][string] $File,
    [Parameter(Mandatory)][string] $PfxPath,
    [string] $PfxPassword = 'test',
    [string] $Subject     = 'CN=NetworkFilter Test'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $PfxPath)) {
    Write-Host "sign.ps1: creating self-signed cert -> $PfxPath"
    $cert = New-SelfSignedCertificate `
        -Type          CodeSigningCert `
        -Subject       $Subject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyUsage      DigitalSignature `
        -KeyAlgorithm  RSA `
        -KeyLength     2048 `
        -HashAlgorithm SHA256 `
        -NotAfter      ((Get-Date).AddYears(10))
    $pw = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $pw | Out-Null

    $cerPath = [System.IO.Path]::ChangeExtension($PfxPath, '.cer')
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-Host "sign.ps1: exported public cert -> $cerPath"
}

& $Signtool sign /fd sha256 /f $PfxPath /p $PfxPassword $File
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE" }
