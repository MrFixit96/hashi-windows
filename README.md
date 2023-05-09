# Windows Install Scripts for Hashicorp Tools
---
## NAME
  Install-Vault.ps1
## SYNOPSIS
  Downloads and Installs Vault and Consul
  
## DESCRIPTION
  This script will:
  * Download the requested Vault and Consul binaries
  * Unzips and install them to the chosen location
  * Write Example Configuration Files
  * Set up Consul ACLs
  
### Requirements:
* This script requires Powershell to be opened as an Administrator
* This script is patterned after the [Vault Reference Architecture](https://learn.hashicorp.com/vault/operations/ops-reference-architecture) as much as possible, and as such uses non-standard ports for Consul backed storage

  Windows Firewall rules must allow access to:
  * port tcp-8200 (vault api)
  * port tcp-8201 (vault replication)
  * port tcp-7300 (consul server)
  * port tcp/udp-7301 (consul Lan Serf)
  * port tcp/udp-7302 (consul Wan Serf)
  * port tcp-7500 (consul http)
  * port tcp-7501 (consul https)
  * port tcp-7600 (consul dns)

### Examples: 
  
* To Install Vault as a service and use Integrated Storage run the following:
  `.\Install-Vault.ps1 -VAULT_VERSION "1.13.2" -Action "Install-Vault" -USE_RAFT "$true"`

* To Simply Install Vault and Consul as a service using the LocalSystem user run the following:,
  `.\Install-Vault.ps1 -CONSUL_VERSION "1.15.2" -VAULT_VERSION "1.13.2"`

* To Install Vault and Consul as a service using unique users (consul and vault), run the following:
  `.\Install-Vault.ps1 -CONSUL_VERSION "1.15.2" -VAULT_VERSION "1.13.2" -Action "Install-All -localuser "$false"`
  
* To Install Vault and Consul as a service using unique users (consul and vault) and to a custom location (default is `C:\Hashicorp\<Vault OR Consul>`), run the following: **noting the back-slashes in the directory paths**
  `.\Install-Vault.ps1 -CONSUL_VERSION "1.15.2" -VAULT_VERSION "1.13.2" -Action "Install-All -localuser "$false" -CONSUL_DIR "C:/<CUSTOM_DIR>" -VAULT_DIR "C:/<CUSTOM_DIR>`  

  ---
