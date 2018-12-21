$ErrorActionPreference = "Stop"

#$subject_alternate_name = "2.5.29.17={text}upn=xxxxxxx"
#$application_policy = "1.3.6.1.4.1.311.21.10={text}xxxxxxx"
#$certificate_policies = "2.5.29.32={text}XXXXXX"
#$name_constraints = "2.5.29.30={text}XXXXXX"
#$policy_mappings = "2.5.29.33={text}XXXXXX"
#$basic_contraints = "2.5.29.19={text}XXXXXX"
#$applciation_policy_Mappings = "1.3.6.1.4.1.311.21.11={text}XXXXXX"

#Enhanced Key Usage={text}Client Authentication,Server Authentication,Secure Email,Code Signing,Timestamp Signing
$enhanced_key_usage = "2.5.29.37={text}1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.4,1.3.6.1.5.5.7.3.3,1.3.6.1.5.5.7.3.8,1.3.6.1.5.5.7.3.9"

$root_certificate_name = "RootCA" #Subject Name, Issuer Name, Subject Alternate Name
$signed_certificate_name = "18.206.45.10"

#create the root certificate
$rootCert = New-SelfSignedCertificate `
    -CertStoreLocation cert:\CurrentUser\My `
    -FriendlyName $root_certificate_name `
    -DnsName $root_certificate_name `
    -TextExtension @($enhanced_key_usage) `
    -KeyExportPolicy Exportable `
    -KeyUsage EncipherOnly, CRLSign, CertSign, KeyAgreement, DataEncipherment, KeyEncipherment, NonRepudiation, DigitalSignature, DecipherOnly

[System.Security.SecureString]$rootcertPassword = ConvertTo-SecureString -String "password" -Force -AsPlainText
[String]$rootCertPath = Join-Path -Path 'cert:\CurrentUser\My\' -ChildPath "$($rootcert.Thumbprint)"

#public binary DER certificate
Export-Certificate -Cert $rootCertPath -FilePath "$($root_certificate_name)_der.crt" -Type CERT

#create the personal certificate
$testCert = New-SelfSignedCertificate `
    -CertStoreLocation cert:\CurrentUser\My `
    -DnsName $signed_certificate_name `
    -FriendlyName $signed_certificate_name `
    -TextExtension @($enhanced_key_usage) `
    -KeyExportPolicy Exportable `
    -Signer $rootCert `
    -KeyUsage EncipherOnly, CRLSign, CertSign, KeyAgreement, DataEncipherment, KeyEncipherment, NonRepudiation, DigitalSignature, DecipherOnly

[String]$testCertPath = Join-Path -Path "cert:\CurrentUser\My\" -ChildPath "$($testCert.Thumbprint)"

#private and public certificate with password
Export-PfxCertificate -Cert $testCertPath -FilePath "$($signed_certificate_name).pfx" -Password $rootcertPassword

#public binary DER certificate
Export-Certificate -Cert $testCertPath -FilePath "$($signed_certificate_name)_der.crt" -Type CERT

#public BASE 64 certificate
certutil -encode "$($signed_certificate_name)_der.crt" "$($signed_certificate_name).pem"

#move the certificate to LocalMachine ROOT (because you can't create a self-signed in there)
Import-Certificate -FilePath "$($root_certificate_name)_der.crt"  -CertStoreLocation "cert:\LocalMachine\Root"
Import-Certificate -FilePath "$($root_certificate_name)_der.crt"  -CertStoreLocation "cert:\CurrentUser\Root"

#remove the temp RootCA certificate from cert:\CurrentUser\My\
Remove-Item -Path $rootCertPath

#convert pfx file to Base64
$fileContentBytes = get-content "$($signed_certificate_name).pfx" -Encoding Byte
[System.Convert]::ToBase64String($fileContentBytes) | Out-File "$($signed_certificate_name).txt"

echo "All Done"