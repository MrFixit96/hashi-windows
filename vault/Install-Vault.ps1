<#
  .SYNOPSIS
  Downloads and Installs Vault and Consul Binaries
  
  .DESCRIPTION
   ###############################################################################################################################
   #
   #	 NAME: Install-Vault.ps1
   #  Author: James Anderton <janderton@hashicorp.com>
   #  Purpose: This script will download the requested Vault and Consul binaries, unzips and installs them to the chosen location
   #
   ###############################################################################################################################
  .Example: 
  .\Vault_Ent_Installer.ps1 -CONSUL_VERSION="1.7.3" -VAULT_VERSION="1.4.2"

#>

Param (
  
  [Parameter(
    Mandatory = $true,
    HelpMessage = 'CONSUL_VERSION is which version you want to download and install')]
  [string] $CONSUL_VERSION = '1.7.3',
 
  [Parameter(
    HelpMessage = 'CONSUL_URL is where to download Consul from. It defaults to https://releases.hashicorp.com/consul')]
  [string] $CONSUL_URL = "https://releases.hashicorp.com/consul",

  [Parameter(
    HelpMessage = '# CONSUL_DIR is where to install Consul. Defaults to C:\Hashicorp\Consul')]
  [string] $CONSUL_DIR = "C:\Program Files\Hashicorp\Consul",

  [Parameter(
    Mandatory,
    HelpMessage = 'VAULT_VERSION is which version you want to download and install')]
  [string] $VAULT_VERSION = '1.4.2',

  [Parameter(
    HelpMessage = 'VAULT_URL is where to download Vault from. It defaults to https://releases.hashicorp.com/vault')]
  [string] $VAULT_URL = "https://releases.hashicorp.com/Vault",

  [Parameter(
    HelpMessage = 'VAULT_DIR is where to install Vault. Defaults to C:\Program Files\Hashicorp\Vault')]
  [string] $VAULT_DIR = "C:\Program Files\Hashicorp\Vault"
)

##############################################################################################
#
#	Get Consul
#
##############################################################################################

# Create Consul Directories to store binaries
if (-not (Test-Path $CONSUL_DIR)){
  mkdir $CONSUL_DIR
  mkdir $CONSUL_DIR\data
}
Set-Location $CONSUL_DIR

# Save Current ProgressBar Preference and set it to Silent because if we dont, 
# Invoke-WebRequest blocks the stream to update the progress bar

$CurrentProgressPref = $ProgressPreference;
$ProgressPreference = "SilentlyContinue";

# Download Consul and its signature/checksum files
Invoke-WebRequest "${CONSUL_URL}/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_windows_amd64.zip" -Outfile consul_${CONSUL_VERSION}_windows_amd64.zip
Invoke-WebRequest "${CONSUL_URL}/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_SHA256SUMS" -Outfile consul_${CONSUL_VERSION}_SHA256SUMS
Invoke-WebRequest "${CONSUL_URL}/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_SHA256SUMS.sig" -Outfile consul_${CONSUL_VERSION}_SHA256SUMS.sig

# Check the hashes to make sure we have valid files
findstr (get-filehash -algorithm SHA256 ${CONSUL_DIR}\consul_${CONSUL_VERSION}_windows_amd64.zip).hash.toLower() ${CONSUL_DIR}\consul_${CONSUL_VERSION}_SHA256SUMS

# Expand out the zipfile to our directory
Expand-Archive -Confirm -Force ${CONSUL_DIR}\consul_${CONSUL_VERSION}_windows_amd64.zip $CONSUL_DIR

# Add Consul directory to the system path (both current and future)
$env:path += ";${CONSUL_DIR}"
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";${CONSUL_DIR}", "Machine")

# Set ProgressBar preference back to normal
$ProgressPreference = $CurrentProgressPref;

############################################################################################
#
#	Get Vault
#
##############################################################################################

# Create Consul Directories to store binaries
if (-not (Test-Path $VAULT_DIR)){
  mkdir $VAULT_DIR
  mkdir $VAULT_DIR\data
}
Set-Location $VAULT_DIR

# Save Current ProgressBar Preference and set it to Silent because if we dont, 
# Invoke-WebRequest blocks the stream to update the progress bar
$CurrentProgressPref = $ProgressPreference;
$ProgressPreference = "SilentlyContinue";

# Download Consul and its signature/checksum files
Invoke-WebRequest "${VAULT_URL}/${VAULT_VERSION}/vault_${VAULT_VERSION}_windows_amd64.zip" -Outfile vault_${VAULT_VERSION}_windows_amd64.zip
Invoke-WebRequest "${VAULT_URL}/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS" -Outfile vault_${VAULT_VERSION}_SHA256SUMS
Invoke-WebRequest "${VAULT_URL}/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS.sig" -Outfile vault_${VAULT_VERSION}_SHA256SUMS.sig

# Check the hashes to make sure we have valid files
findstr (get-filehash -algorithm SHA256 ${VAULT_DIR}\vault_${VAULT_VERSION}_windows_amd64.zip).hash.toLower() ${VAULT_DIR}\vault_${VAULT_VERSION}_SHA256SUMS

# Expand out the zipfile to our directory
Expand-Archive -Confirm -Force $ ${VAULT_DIR}\vault_${VAULT_VERSION}_windows_amd64.zip $VAULT_DIR

# Set ProgressBar preference back to normal
$ProgressPreference = $CurrentProgressPref;

######################################################################################################
#
# Create and configure Services    
#
######################################################################################################

# Create consul-server.hcl
New-Item -type file -Path $CONSUL_DIR -name consul-server.hcl

$multiline_string = @'
 This
   is
     my
       System.String.
'@

echo $multiline_string > $CONSUL_DIR\consul-server.hcl

# Create vault-server.hcl
New-Item -type file -Path $VAULT_DIR -name vault-server.hcl

$multiline_string = @'
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "C:\\path\\to\\fullchain.pem"
  tls_key_file  = "C:\\path\\to\\privkey.pem"
}

seal "pkcs11" {
  lib            = "C:\\Vault\\cryptoki.dll"
  slot           = "0"
  pin            = "AAAA-BBBB-CCCC-DDDD"
  key_label      = "vault-hsm-key"
  hmac_key_label = "vault-hsm-hmac-key"
}

storage "raft" {
  path = "$CONSUL_DIR\\data"
  node_id = "raft_node_1"
}

#telemetry {
#  statsite_address = "statsite.company.local:8125"
#}

#api_addr = "{{ full URL to Vault API endpoint }}"

ui = true

'@

echo $multiline_string > $VAULT_DIR\vault-server.hcl