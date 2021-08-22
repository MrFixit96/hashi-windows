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
####################################################
#  Globals
####################################################
Param (
  
  [Parameter(
    HelpMessage = 'CONSUL_VERSION is which version you want to download and install')]
  [string] $CONSUL_VERSION = '1.8.2',
 
  [Parameter(
    HelpMessage = 'CONSUL_URL is where to download Consul from. It defaults to https://releases.hashicorp.com/consul')]
  [string] $CONSUL_URL = 'https://releases.hashicorp.com/consul',

  [Parameter(
    HelpMessage = '# CONSUL_DIR is where to install Consul. Defaults to C:\Hashicorp\Consul')]
  [string] $CONSUL_DIR = "C:/Hashicorp/Consul",

  [Parameter(
    HelpMessage = 'VAULT_VERSION is which version you want to download and install')]
  [string] $VAULT_VERSION = '1.7.3',

  [Parameter(
    HelpMessage = 'VAULT_URL is where to download Vault from. It defaults to https://releases.hashicorp.com/vault')]
  [string] $VAULT_URL = 'https://releases.hashicorp.com/vault',

  [Parameter(
    HelpMessage = 'VAULT_DIR is where to install Vault. Defaults to C:\\Program Files\\Hashicorp\\Vault')]
  [string] $VAULT_DIR = "C:/Hashicorp/Vault",  

  [Parameter(
    HelpMessage = 'Whether to use Consul or Raft in Vault backend config')]
  [string] $USE_RAFT = $null,

  [Parameter(
    HelpMessage = 'Specify which action to take (Install-All, Install-Vault, Install-Consul)')]
  [string] $Action,

  [Parameter(
    HelpMessage = 'Specify whether to create Consul Service using LocalSystem account or a dedicated account name consul (default :$true == LocalSystem)')]
  [string] $serviceUser = $true 

  )

 ##############################################################################################
#
#	 Main
#
############################################################################################## 
Function Main {

  $location = (get-location).path

  if ($Action){
    switch ($Action) {
      'Install-Vault' { Install-Vault
                        Configure-Vault
                        Create-Certs-Vault
                        Start-Vault
      }
      'Install-Consul' { Install-Consul 
                        Configure-Consul
                        Create-Certs-Vault
                        Setup-ACL
                        Start-Consul
      }
      'Install-All' { Install-All
      }
      'Uninstall-All' { Uninstall-All
      }

      Default { Install-All }
    }
  }
}

###############################################################################################
#
#	 Install-All
#
##############################################################################################
Function Install-All {
  # Install and Configure Consul Storage Backend First
  write-host "Installing ${CONSUL_DIR}/Consul.exe"
  Install-Consul | Out-Null

  write-host "Writing ${CONSUL_DIR}/consul-server.hcl"
  Configure-Consul | Out-Null

  write-host "Writing TLS Certs to ${CONSUL_DIR}/certs/"
  Create-Certs-Consul | Out-Null

  write-host "Starting the Consul Service"
  Start-Consul | Out-Null
  Start-Sleep -Seconds 10
 
  write-host "Bootstrapping Consul ACL System"
  Setup-ACL | Out-Null

  # Install and Configure Vault Server
  Install-Vault | Out-Null
  Configure-Vault | Out-Null
  Create-Certs-Vault | Out-Null
  # Configure Consul Agent on Vault Server to connect to backend cluster
  #Configure-Consul-Agent

  Start-Vault

  $env:VAULT_HTTP_ADDR="https://127.0.0.1:8200"
  $env:CONSUL_HTTP_ADDR="https://127.0.0.1:7501"

  $env:VAULT_CACERT="${VAULT_DIR}/certs/consul-agent-ca.pem" 
  $env:VAULT_CLIENT_KEY="${VAULT_DIR}/certs/dc1-client-consul-0-key.pem"
  $env:VAULT_CLIENT_CERT="${VAULT_DIR}/certs/dc1-client-consul-0.pem"

  $env:CONSUL_CACERT="${CONSUL_DIR}/certs/consul-agent-ca.pem"
  $env:CONSUL_CLIENT_KEY="${CONSUL_DIR}/certs/dc1-client-consul-0-key.pem"
  $env:CONSUL_CLIENT_CERT="${CONSUL_DIR}/certs/dc1-client-consul-0.pem"

  $env:CONSUL_HTTP_SSL="true"
  $env:CONSUL_TOKEN=${env:CONSUL_MGMNT_TOKEN}

  write-host "`n CONSUL MANAMGENT TOKEN: $env:CONSUL_MGMT_TOKEN `n"
  write-host "`n CONSUL AGENT TOKEN:     $env:CONSUL_AGENT_TOKEN `n"
  write-host "`n CONSUL VAULT TOKEN:     $env:CONSUL_VAULT_TOKEN `n"
  consul members list
  vault status

}

###############################################################################################
#
#	 Uninstall-All
#
##############################################################################################
Function Uninstall-All {
try {
  if ((get-service vault -ErrorAction "ignore").Name -match "Vault"){
    nssm stop vault
    nssm remove vault
  }
  if ((get-service consul -ErrorAction "ignore").Name -match "Consul"){
    stop-service consul
    if ($PSVersionTable.PSVersion.Major -eq 5){
      write-host "Please Edit the Registry to remove the Consul Service"
    } ElseIf ($PSVersionTable.PSVersion.Major -ge 7){
      Remove-Service consul
    }
  }
  if ((Get-LocalUser vault -ErrorAction "ignore").Name -match "vault"){
    Remove-LocalUser -Name "Vault"
  }
  if ((Get-LocalUser consul -ErrorAction "ignore").Name -match "consul"){
    Remove-LocalUser -Name "Consul"
  }
  if (test-path $CONSUL_DIR -ErrorAction "ignore"){
    Remove-Item -Force "$CONSUL_DIR"
  }
  if (test-path $VAULT_DIR -ErrorAction "ignore"){
    Remove-Item -Force "$VAULT_DIR"
  }
  if (test-path "C:\nssm-2.24" -ErrorAction "ignore"){
    Remove-Item -Force "C:\nssm-2.24"
  }
}
catch {
  "Uninstall Failed - please manually remove files, users and services"
}

}
##############################################################################################
#
#	Install-Consul
#
##############################################################################################
Function Install-Consul {


  # Create Consul Directories to store binaries
  if (-not (Test-Path "$CONSUL_DIR")){
    mkdir "$CONSUL_DIR"
    mkdir "$CONSUL_DIR/data"
  
    Set-Location "$CONSUL_DIR"

    # Save Current ProgressBar Preference and set it to Silent because if we dont, 
    # Invoke-WebRequest blocks the stream to update the progress bar

    $CurrentProgressPref = $ProgressPreference;
    $ProgressPreference = "SilentlyContinue";

    # Download Consul and its signature/checksum files
    Invoke-WebRequest "${CONSUL_URL}/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_windows_amd64.zip" -Outfile consul_${CONSUL_VERSION}_windows_amd64.zip
    Invoke-WebRequest "${CONSUL_URL}/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_SHA256SUMS" -Outfile consul_${CONSUL_VERSION}_SHA256SUMS
    Invoke-WebRequest "${CONSUL_URL}/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_SHA256SUMS.sig" -Outfile consul_${CONSUL_VERSION}_SHA256SUMS.sig

    # Check the hashes to make sure we have valid files
    get-content "${CONSUL_DIR}/*SHA256SUMS"| select-string  (get-filehash -algorithm SHA256 "${CONSUL_DIR}/consul_${CONSUL_VERSION}_windows_amd64.zip").hash.toLower()

    # Expand out the zipfile to our directory
    Expand-Archive -Confirm:$false -Force:$true "${CONSUL_DIR}/consul_${CONSUL_VERSION}_windows_amd64.zip" "$CONSUL_DIR"

    # Set ProgressBar preference back to normal
    $ProgressPreference = $CurrentProgressPref;

  }

  Set-Location "$CONSUL_DIR"

  # Add Consul directory to the system path (both current and future)
  $env:path += ";${CONSUL_DIR}"
  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "Machine") + ";${CONSUL_DIR}", "Machine")


}
############################################################################################
#
#	Install-Vault
#
##############################################################################################
Function Install-Vault {

  # Create Vault Directories to store binaries
  if (-not (Test-Path "$VAULT_DIR")){
    mkdir "$VAULT_DIR"
    mkdir "$VAULT_DIR/data"
  
    Set-Location "$VAULT_DIR"

    # Save Current ProgressBar Preference and set it to Silent because if we dont, 
    # Invoke-WebRequest blocks the stream to update the progress bar
    $CurrentProgressPref = $ProgressPreference;
    $ProgressPreference = "SilentlyContinue";

    # Download Consul and its signature/checksum files
    Invoke-WebRequest "${VAULT_URL}/${VAULT_VERSION}/vault_${VAULT_VERSION}_windows_amd64.zip" -Outfile vault_${VAULT_VERSION}_windows_amd64.zip
    Invoke-WebRequest "${VAULT_URL}/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS" -Outfile vault_${VAULT_VERSION}_SHA256SUMS
    Invoke-WebRequest "${VAULT_URL}/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS.sig" -Outfile vault_${VAULT_VERSION}_SHA256SUMS.sig

    # Check the hashes to make sure we have valid files
    get-content "${VAULT_DIR}/*SHA256SUMS" | select-string  (get-filehash -algorithm SHA256 "${VAULT_DIR}/vault_${VAULT_VERSION}_windows_amd64.zip").hash.toLower()

    # Expand out the zipfile to our directory
    Expand-Archive -Confirm:$false -Force:$true ${VAULT_DIR}/vault_${VAULT_VERSION}_windows_amd64.zip $VAULT_DIR
  }

  # Add Vault directory to the system path (both current and future)
  $env:path += ";${VAULT_DIR}"
  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "Machine") + ";${VAULT_DIR}", "Machine")

  # Set ProgressBar preference back to normal
  $ProgressPreference = $CurrentProgressPref;
}
######################################################################################################
#
# Create and configure Consul Services    
#
######################################################################################################
Function Configure-Consul {
    # Create consul-server.hcl
    New-Item -type file -Path "$CONSUL_DIR" -name consul-server.hcl

@"
datacenter = `"dc1`"
data_dir = "${CONSUL_DIR}/data"
enable_script_checks    = false
disable_remote_exec     = true
#retry_join = [`"xxx.xxx.xxx.xxx`"]

performance {
  raft_multiplier = 1
}

server = true
bootstrap_expect = 1

log_file = "${CONSUL_DIR}/consul.log"
log_rotate_bytes = 102400

ca_file = "${CONSUL_DIR}/certs/consul-agent-ca.pem"
cert_file = "${CONSUL_DIR}/certs/dc1-server-consul-0.pem"
key_file = "${CONSUL_DIR}/certs/dc1-server-consul-0-key.pem"
verify_incoming = true
verify_outgoing = true
verify_server_hostname = true

ui = true

addresses {
  http  = `"0.0.0.0`"
  https = `"0.0.0.0`"
  dns   = `"0.0.0.0`"
}

ports {
  dns         = 7600
  http        = 7500
  https       = 7501
  serf_lan    = 7301
  serf_wan    = 7302
  server      = 7300
}
client_addr = `"0.0.0.0`"

"@ | Out-File -Encoding ASCII -FilePath "${CONSUL_DIR}/consul-server.hcl"

    # Execute Consul command to create a gossip key and store it in consul-server.hcl file
    $enc_key=(consul keygen)
    Add-Content -Path "${CONSUL_DIR}/consul-server.hcl" -Value "encrypt = `"$enc_key`""

    $bind_ip=(get-netipaddress -AddressFamily IPv4 -interfaceAlias Ethernet).ipaddress 
    Add-Content -Path "${CONSUL_DIR}/consul-server.hcl" -Value "bind_addr = `"$bind_ip`""

# Create consul-acl.hcl

@'
acl {
  enabled = true,
  default_policy = "allow",
  enable_token_persistence = true
}
'@  | Out-File -Encoding ASCII -FilePath "${CONSUL_DIR}/consul-acl.hcl"

# Create consul-telemetry.hcl
@'
// UnComment These Lines to forward telemetry 
/*
telemetry {
  metrics_path: '/v1/agent/metrics'
  params:
    format: ['prometheus']

  statsite_address = "statsite.company.local:8125"
}
*/
'@ | Out-File -Encoding ASCII -FilePath "${CONSUL_DIR}/consul-telemetry.hcl"

    ############################
    # Create a unique, non-privileged system user to run Consul.
    $password = (-join ((0x30.. 0x39) + ( 0x41.. 0x5A) + ( 0x61.. 0x7A) | Get-Random -Count 16 | % {[char]$_}))
    $securePassword = (ConvertTo-SecureString -AsPlainText -Force -String $password)

  if (-not ((get-localuser consul -ErrorAction "ignore").Name -match "consul")){
    New-LocalUser "consul" -FullName "Consul User" -Description "Consul Service Account" -Password $securePassword
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential("consul", $securePassword)
  }

  # Local GPO is not able to be edited natively via PowerShell. Please Set account logon rights manually

  try {
  # Create the Consul Service
  if (-not  ((get-service consul -ErrorAction "ignore").Name -match "Consul")){
    write-host "Creating Service Consul"
    if ($serviceUser -eq $true) {
      write-host "Creating Consul Service with LocalSystem User"
      New-Service -Name Consul -BinaryPathName "${CONSUL_DIR}/consul.exe agent -config-dir=${CONSUL_DIR}"  -DisplayName Consul -Description "Hashicorp Consul Service https://consul.io" -StartupType "Automatic"
    } else {
      Write-host "Add 'Consul' User to the Local or AD GPO Policy to LogOnAsAservice"
      write-host "Creating Consul Service with Consul User"
      New-Service -Name Consul -BinaryPathName "${CONSUL_DIR}/consul.exe agent -config-dir=${CONSUL_DIR}"  -DisplayName Consul -Description "Hashicorp Consul Service https://consul.io" -StartupType "Automatic" -Credential $Credential
    }
  }
  }
  catch {
    "Could not create Consul Service"
  }
}

######################################################################################################
#
# Create and configure Vault Services    
#
######################################################################################################
Function Configure-Vault {
# Create vault-server.hcl
New-Item -type file -Path "$VAULT_DIR" -name vault-server.hcl

@"

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "${CONSUL_DIR}/certs/dc1-server-consul-0.pem"
  tls_key_file  = "${CONSUL_DIR}/certs/dc1-server-consul-0-key.pem"
}

//api_addr = "{{ full URL to Vault API endpoint }}"

ui = true

# Disable Mlock because we're on Windows and it uses VirtualLock instead
disable_mlock = true

"@  | Out-File -Encoding ASCII -FilePath "${VAULT_DIR}/vault-server.hcl"

    # Add Cluster_Addr to vault-server.hcl
    $cluster_ip ="cluster_addr = `"https://" + (get-netipaddress -AddressFamily IPv4 -interfaceAlias Ethernet).ipaddress + "`""
    Add-Content -Encoding ASCII -Path ${VAULT_DIR}/vault-server.hcl -Value $cluster_ip

    # Add api_addr to vault-server.hcl
    $api_ip ="api_addr = `"https://" + (get-netipaddress -AddressFamily IPv4 -interfaceAlias Ethernet).ipaddress + "`""
    Add-Content -Encoding ASCII -Path ${VAULT_DIR}/vault-server.hcl -Value $api_ip

if ($USE_RAFT){
# Create vault-storage-raft.hcl
@"
storage "raft" {
  path = "${VAULT_DIR}/data"
  node_id = "raft_node_1"
}

"@  | Out-File -Encoding ASCII -FilePath "${VAULT_DIR}/vault-raft-storage.hcl"
} else {

@"
  storage "consul" {
    address         = "127.0.0.1:7501"
    path            = "vault/"
    scheme          = "https"
    token           = "${CONSUL_VAULT_TOKEN}"
    tls_cert_file = "${CONSUL_DIR}/certs/dc1-server-consul-0.pem"
    tls_key_file  = "${CONSUL_DIR}/certs/dc1-server-consul-0-key.pem"
    tls_skip_verify = "true"
  }

"@  | Out-File -Encoding ASCII -FilePath "${VAULT_DIR}/vault-consul-storage.hcl"

}
<# UnComment These Lines to use AutoUnseal

# Create vault-seal.hcl
@"
seal "pkcs11" {
  lib            = "${VAULT_DIR}\\cryptoki.dll"
  slot           = "0"
  pin            = "AAAA-BBBB-CCCC-DDDD"
  key_label      = "vault-hsm-key"
  hmac_key_label = "vault-hsm-hmac-key"
}

"@ | Out-File -Encoding ASCII -FilePath "${VAULT_DIR}/vault-seal.hcl"

<#
# UnComment These Lines to forward telemetry 
# Create vault-telemetry.hcl
@'
telemetry {
  statsite_address = "statsite.company.local:8125"
}

'@  | Out-File -Encoding ASCII -FilePath "${VAULT_DIR}/vault-telemetry.hcl"
#>

    ############################
    # Create a unique, non-privileged system user to run Vault.
    try {
        $password = (-join ((0x30.. 0x39) + ( 0x41.. 0x5A) + ( 0x61.. 0x7A) | Get-Random -Count 16 | % {[char]$_}))
        $securePassword = (ConvertTo-SecureString -AsPlainText -Force -String $password)

        if (-not ((get-localuser vault -ErrorAction "ignore").Name -match "vault")){    
          New-LocalUser "vault" -FullName "Vault User" -Description "Vault Service Account" -Password $securePassword
          $Credential = New-Object -TypeName System.Management.Automation.PSCredential("vault", $securePassword)
        }

        $acl = Get-Acl ${VAULT_DIR}

        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(".\vault","FullControl","Allow")

        $acl.SetAccessRule($AccessRule)

        $acl | Set-Acl ${VAULT_DIR}
        }
    catch {
        "[ERROR] Could not create Vault User"
    }

    # Create the Vault Service 
    # ***** Because Unlike Consul and Nomad, the Vault binary doesnt currently support the WinSVC System Calls required to use built-in Windows Service Manager
    # ***** So we must install a service manager for binaries. NSSM is a widely used option.

    # Save Current ProgressBar Preference and set it to Silent because if we dont, 
    # Invoke-WebRequest blocks the stream to update the progress bar
    $CurrentProgressPref = $ProgressPreference;
    $ProgressPreference = "SilentlyContinue";

    # Download NSSM
    if (-not (Test-Path "c:\nssm-2.24")){ 
      Invoke-WebRequest http://nssm.cc/release/nssm-2.24.zip -Outfile "${home}\Downloads\nssm-2.24.zip"
      Expand-Archive -Force "${home}\Downloads\nssm-2.24.zip" "C:\"
      $env:Path=$env:Path+";c:\nssm-2.24\win64\"
      [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "Machine") + ";C:\nssm-2.24\win64\", "Machine")
    }

    #Create Service and Start it
  try {
    if (-not ((get-service vault -ErrorAction "ignore").Name -match "Vault" )){
      if ($serviceUser -eq $true){
        $FileExe="${VAULT_DIR}/vault.exe"
        echo "Creating Vault Service"
        
        nssm install Vault "$FileExe"
        nssm set Vault AppParameters "server -config=${VAULT_DIR}"
        nssm set Vault AppDirectory  "${VAULT_DIR}"
        nssm set Vault Description "Hashicorp Vault Service https://vaultproject.io"
        nssm set Vault Start SERVICE_AUTO_START
        #nssm set Vault ObjectName vault $securePassword

        # This is what it would look like if Vault could use the native manager and LocalSystem User
        #New-Service -Name Vault-Svc -BinaryPathName "${VAULT_DIR}\vault.exe server -config=${VAULT_DIR}"  -DisplayName Vault-Svc -Description "Hashicorp Vault Service https://vaultproject.io" -StartupType "Automatic"
        # This is what it would look like if Vault could use the native manager and a unique user
        #New-Service -Name Vault -BinaryPathName "${VAULT_DIR}\vault.exe -config=${VAULT_DIR}"  -DisplayName Vault -Description "Hashicorp Vault Service https://vaultproject.io" -StartupType "Automatic" -Credential $Credential
      }
    }
  }
  catch {
    "[ERROR] Could not create Vault Service"
  }
}

######################################################################################################
#
# Create or import TLS Certificates    
#
######################################################################################################
Function Create-Certs-Vault {
 
  #If Consul isnt present, download Consul and Install it just to generate Certs
  if (-not (Test-Path "$CONSUL_DIR/consul.exe")){
    Install-Consul
  }
  mkdir "${VAULT_DIR}/certs"

  if (-not (Test-Path "$CONSUL_DIR/certs")){
    Create-Certs-Consul
    Set-Location "${CONSUL_DIR}/certs"
  }

  # Execute Consul command to create the CA Cert we'll be building the rest of our certs from
  consul tls ca create

  # Execute the Consul command to create the server certs
  consul tls cert create -server -dc "dc1"

  # Run the following command with the -client flag to create client certificates. The file name increments automatically.
  consul tls cert create -client -dc "dc1"

  # You must distribute the CA certificate, consul-agent-ca.pem, to each of the Consul agent instances as well as the agent specific cert and private key.


  Copy-Item "${CONSUL_DIR}/certs/*" -Destination "${VAULT_DIR}/certs/" -Confirm:$false
  Set-Location $location

}
################
Function Create-Certs-Consul {

  #If Consul isnt present, download Consul and Install it just to generate Certs
  if (-not (Test-Path "$CONSUL_DIR/consul.exe")){
    Install-Consul
  }

  if (-not (Test-Path "$CONSUL_DIR/certs")){
    mkdir "${CONSUL_DIR}/certs"
  }
 
  Set-Location "${CONSUL_DIR}/certs"

  # Execute Consul command to create the CA Cert we'll be building the rest of our certs from
  consul tls ca create

  # Execute the Consul command to create the server certs
  consul tls cert create -server -dc "dc1"

  # Run the following command with the -client flag to create client certificates. The file name increments automatically.
  consul tls cert create -client -dc "dc1"

  # You must distribute the CA certificate, consul-agent-ca.pem, to each of the Consul agent instances as well as the agent specific cert and private key.


  Set-Location $location

}

######################################################################################################
#
# Bootstrap the Consul ACL system and create policies/tokens
#
#####################################################################################################
Function Setup-ACL {

  # If Consul isnt present, download Consul and Install it just to generate Certs
  if (-not ((get-service consul).status -match "Running") -eq $true){
    Install-Consul
    start-service consul
  }
    
  if (-not (Test-Path "$CONSUL_DIR/policies")){
    mkdir "$CONSUL_DIR/policies"
  }

  $env:CONSUL_HTTP_ADDR="https://127.0.0.1:7501"
  $env:CONSUL_CACERT="${CONSUL_DIR}/certs/consul-agent-ca.pem"
  $env:CONSUL_CLIENT_KEY="${CONSUL_DIR}/certs/dc1-client-consul-0-key.pem"
  $env:CONSUL_CLIENT_CERT="${CONSUL_DIR}/certs/dc1-client-consul-0.pem"
  $env:CONSUL_HTTP_SSL="true"

  $acl_tokens = (consul acl bootstrap)

  #Set the CONSUL_MGMT_TOKEN environment variable so we can create policies
  $env:CONSUL_MGMT_TOKEN = `
  foreach ( $token in $acl_tokens){
    if ($token.Split(':')[0] -match "SecretID") {($token.Split(':')[1]).trim();}
  }
  

# Create the node policy file
@'
agent_prefix "" {
  policy = "write"
}
node_prefix "" {
  policy = "write"
}
service_prefix "" {
  policy = "read"
}
session_prefix "" {
  policy = "read"
}

'@  | Out-File -Encoding ASCII -FilePath "${CONSUL_DIR}/policies/node-policy.hcl"

# Generate Vault Policy
@'
{
  "key_prefix": {
    "vault/": {
      "policy": "write"
    }
  },
  "node_prefix": {
    "": {
      "policy": "write"
    }
  },
  "service": {
    "vault": {
      "policy": "write"
    }
  },
  "agent_prefix": {
    "": {
      "policy": "write"
    }
  },
  "session_prefix": {
    "": {
      "policy": "write"
    }
  }
}
'@   | Out-File -Encoding ASCII -FilePath "${CONSUL_DIR}/policies/vault-policy.hcl"

  # Generate the Consul Node ACL Policy
  consul acl policy create -token "${env:CONSUL_MGMT_TOKEN}" -name "node-policy" -rules "@${CONSUL_DIR}/policies/node-policy.hcl"

  # Generate the Consul ACL Policy for Vault App
  consul acl policy create -token "${env:CONSUL_MGMT_TOKEN}" -name "vault-policy" -rules "@${CONSUL_DIR}/policies/vault-policy.hcl"

  # Create the node token with the newly created policy.
  $acl_tokens = (consul acl token create -token "${env:CONSUL_MGMT_TOKEN}" -description "node token" -policy-name "node-policy")

  $env:CONSUL_AGENT_TOKEN  = `
  foreach ( $token in $acl_tokens){
    if ($token.Split(':')[0] -match "SecretID") {($token.Split(':')[1]).trim();}
  }

  # Create the vault token with the newly created policy.
  $acl_tokens = (consul acl token create -token "${env:CONSUL_MGMT_TOKEN}" -description "vault app token" -policy-name "vault-policy")
  $env:CONSUL_VAULT_TOKEN  = `
  foreach ( $token in $acl_tokens){
    if ($token.Split(':')[0] -match "SecretID") {($token.Split(':')[1]).trim();}
  }

  # On all Consul Servers add the node token
  consul acl set-agent-token -token "${env:CONSUL_MGMT_TOKEN}" agent "$env:CONSUL_AGENT_TOKEN"
  
  write-debug "`n CONSUL MANAMGENT TOKEN: $env:CONSUL_MGMT_TOKEN `n"
  write-debug "`n CONSUL AGENT TOKEN:     $env:CONSUL_AGENT_TOKEN `n"
  write-debug "`n CONSUL VAULT TOKEN:     $env:CONSUL_VAULT_TOKEN `n"
  
  
}
######################################################################################################
#
# Start Consul Service
#
#####################################################################################################
Function Start-Consul {
  
  start-service consul
  
  # Use this to start it manually
  #consul.exe agent -config-dir="${CONSUL_DIR}"
}

######################################################################################################
#
# Start Vault Service
#
#####################################################################################################
Function Start-Vault {
  # Call NSSM to start Vault Service
  & "C:\nssm-2.24\win64\nssm.exe" start Vault
  #start-service vault

  # Use this to start it manually
  #vault.exe server -config="${VAULT_DIR}"
}
###################################################################################################################

### Start Program
Main
