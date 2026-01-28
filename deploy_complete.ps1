# deploy-3-networks.ps1 - Créer 3 réseaux et déployer les VMs
# Exécuter en admin
function Get-VMwareInventoryPath {
    <#
    .SYNOPSIS
    Trouve dynamiquement le fichier inventory.vmls de VMware
    #>
    $inventoryPath = "$env:APPDATA\VMware\inventory.vmls"
    
    if (Test-Path $inventoryPath) {
        return $inventoryPath
    } else {
        Write-Host "Fichier inventory.vmls non trouvé à: $inventoryPath" -ForegroundColor Yellow
        return $null
    }
}

function Add-VMToInventory {
    <#
    .SYNOPSIS
    Ajoute une VM à l'inventaire VMware au format correct
    .PARAMETER VMXPath
    Chemin complet du fichier .vmx de la VM
    .PARAMETER DisplayName
    Nom affiché de la VM dans VMware
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMXPath,
        
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )
    
    $inventoryPath = Get-VMwareInventoryPath
    
    if (-not $inventoryPath) {
        Write-Host "Impossible d'ajouter la VM à l'inventaire" -ForegroundColor Red
        return $false
    }
    
    # Lire l'inventaire existant
    $content = Get-Content $inventoryPath -Raw
    
    # Trouver le prochain numéro de slot disponible
    $matches = [regex]::Matches($content, 'vmlist(\d+)\.config')
    $maxNum = 0
    foreach ($match in $matches) {
        $num = [int]$match.Groups[1].Value
        if ($num -gt $maxNum) { $maxNum = $num }
    }
    $nextNum = $maxNum + 1
    
    # Créer l'UUID pour la VM
    $uuid = [guid]::NewGuid().ToString()
    
    # Ajouter les entrées dans le format VMware
    $newEntries = @"

vmlist$nextNum.config = "$VMXPath"
vmlist$nextNum.DisplayName = "$DisplayName"
vmlist$nextNum.ParentID = "0"
vmlist$nextNum.ItemID = "$nextNum"
vmlist$nextNum.SeqID = "0"
vmlist$nextNum.IsFavorite = "FALSE"
vmlist$nextNum.IsClone = "FALSE"
vmlist$nextNum.CfgVersion = "8"
vmlist$nextNum.State = "normal"
vmlist$nextNum.UUID = "$(Generate-UUID)"
vmlist$nextNum.IsCfgPathNormalized = "TRUE"
vmlist.$uuid = "$VMXPath"
"@
    
    # Ajouter à l'inventaire
    $content += $newEntries
    
    # Sauvegarder
    Set-Content -Path $inventoryPath -Value $content
    
    Write-Host "[ok] VM ajoutée à l'inventaire: $DisplayName (slot $nextNum)" -ForegroundColor Green
    return $true
}

function Generate-UUID {
    <#
    .SYNOPSIS
    Génère un UUID au format VMware (HEX formaté)
    #>
    $guid = [guid]::NewGuid()
    $bytes = $guid.ToByteArray()
    $hex = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join " "
    return $hex.Substring(0, 23) + "-" + $hex.Substring(24)
}

function Get-VMwareInventoryContent {
    <#
    .SYNOPSIS
    Récupère le contenu de l'inventaire VMware
    #>
    $inventoryPath = Get-VMwareInventoryPath
    
    if (-not $inventoryPath) {
        return $null
    }
    
    return Get-Content $inventoryPath -Raw
}

$vnetlib = "C:\Program Files (x86)\VMware\VMware Workstation\vnetlib.exe"

if (-not (Test-Path $vnetlib)) {
    Write-Host "ERREUR: vnetlib.exe non trouvé!" -ForegroundColor Red
    exit 1
}

# Vérifier admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERREUR: Exécuter en tant qu'administrateur!" -ForegroundColor Red
    exit 1
}

# Configuration des 3 réseaux
$networks = @(
    @{ Name = "R1"; VMnet = 2; Subnet = "192.168.10.0"; Netmask = "255.255.255.0"; Gateway = "192.168.10.130"; AdapterIP = "192.168.10.130" },
    @{ Name = "R2"; VMnet = 3; Subnet = "192.168.20.0"; Netmask = "255.255.255.0"; Gateway = "192.168.20.110"; AdapterIP = "192.168.20.110" },
    @{ Name = "R3"; VMnet = 4; Subnet = "192.168.30.0"; Netmask = "255.255.255.0"; Gateway = "192.168.30.120"; AdapterIP = "192.168.30.120" }
)

Write-Host "=== Configuration de 3 réseaux VMware ===" -ForegroundColor Cyan

foreach ($net in $networks) {
    Write-Host "`n--- $($net.Name) (VMnet$($net.VMnet): $($net.Subnet)/$($net.Netmask)) ---" -ForegroundColor Yellow
    
    # Vérifier si l'adaptateur existe déjà
    $adapter = Get-NetAdapter | Where-Object { $_.Name -like "*VMnet$($net.VMnet)*" }
    
    if ($adapter) {
        Write-Host "[SKIP] Déjà créé" -ForegroundColor Yellow
        continue
    }
    
    & $vnetlib -- add adapter "vmnet$($net.VMnet)" | Out-Null
    & $vnetlib -- set vnet "vmnet$($net.VMnet)" addr $net.Subnet | Out-Null
    & $vnetlib -- set vnet "vmnet$($net.VMnet)" mask $net.Netmask | Out-Null
    & $vnetlib -- add dhcp "vmnet$($net.VMnet)" | Out-Null
    Write-Host "[ok] Adaptateur configuré" -ForegroundColor Green
    Start-Sleep -Seconds 3
    netsh interface ip set address "VMware Network Adapter VMnet$($net.VMnet)" static $net.AdapterIP $net.Netmask | Out-Null
    Write-Host "[ok] IP $($net.AdapterIP)/24 configurée" -ForegroundColor Green
}

# ===== DÉPLOIEMENT DES VMS =====
Write-Host "`n`n=== Déploiement des VMs ===" -ForegroundColor Cyan

$ovasFolder = ".\vms_ovas"

# Trouver le dossier des VMs de VMware dynamiquement
Write-Host "Recherche du dossier des VMs VMware..." -ForegroundColor Cyan
$prefsFile = "$env:APPDATA\VMware\preferences.ini"

if (Test-Path $prefsFile) {
    $prefs = Get-Content $prefsFile -Raw
    $vmxPath = [regex]::Match($prefs, 'pref\.mruVM0\.filename\s*=\s*"([^"]+)"').Groups[1].Value
    
    if ($vmxPath) {
        $vmFolder = Split-Path -Parent (Split-Path -Parent $vmxPath)
        Write-Host "Dossier trouvé: $vmFolder" -ForegroundColor Green
    } else {
        Write-Host "Impossible de trouver le dossier. Utilisation par défaut..." -ForegroundColor Yellow
        $vmFolder = "$env:USERPROFILE\OneDrive\Documents\Virtual Machines"
    }
} else {
    Write-Host "Fichier preferences.ini non trouvé. Utilisation par défaut..." -ForegroundColor Yellow
    $vmFolder = "$env:USERPROFILE\OneDrive\Documents\Virtual Machines"
}

# Vérifier ovftool
$ovftool = Get-ChildItem "C:\Program Files*" -Filter "ovftool.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.FullName }
$logPath = "$env:APPDATA\Local\Temp\vmware-$env:USERNAME\ovftool-logs"

if (-not $ovftool) {
    Write-Host "[ERREUR] ovftool.exe non trouvé!" -ForegroundColor Red
    Write-Host "Installe VMware OVF Tool: https://my.vmware.com" -ForegroundColor Yellow
    exit 1
}

Write-Host "ovftool trouvé: $ovftool" -ForegroundColor Green

if (-not (Test-Path $vmFolder)) {
    New-Item -ItemType Directory -Path $vmFolder -Force | Out-Null
}

if (-not (Test-Path $ovasFolder)) {
    Write-Host "Dossier vms_ovas créé. Ajoute les fichiers OVA dedans." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $ovasFolder -Force | Out-Null
    exit 0
}

$ovaFiles = Get-ChildItem -Path $ovasFolder -Filter "*.ova" -ErrorAction SilentlyContinue

if ($ovaFiles.Count -eq 0) {
    Write-Host "Aucun fichier OVA trouvé dans $ovasFolder" -ForegroundColor Yellow
    exit 0
}

Write-Host "Trouvé $($ovaFiles.Count) OVA(s) à déployer`n" -ForegroundColor Green

# Configuration des VMs (mapping OVA -> config réseau)
$vmConfigs = @{
    "TLS-DC-01" = @{ NICs = @(
        @{ Idx = 1; VMnet = 2; IP = "192.168.10.110"; Mask = "255.255.255.0"; GW = "192.168.10.130" },
        @{ Idx = 2; VMnet = 3; IP = "192.168.20.110"; Mask = "255.255.255.0"; GW = "192.168.20.110" }
    )}
    "SRV-WEB-01" = @{ NICs = @(
        @{ Idx = 1; VMnet = 2; IP = "192.168.10.130"; Mask = "255.255.255.0"; GW = "192.168.10.130" }
    )}
    "SRV-WINDOWS-01" = @{ NICs = @(
        @{ Idx = 1; VMnet = 2; IP = "192.168.10.120"; Mask = "255.255.255.0"; GW = "192.168.10.130" }
    )}
    "GRE-DC-01" = @{ NICs = @(
        @{ Idx = 1; VMnet = 3; IP = "192.168.20.120"; Mask = "255.255.255.0"; GW = "192.168.20.110" },
        @{ Idx = 2; VMnet = 4; IP = "192.168.30.120"; Mask = "255.255.255.0"; GW = "192.168.30.120" }
    )}
    "SRV-WINDOWS-02" = @{ NICs = @(
        @{ Idx = 1; VMnet = 4; IP = "192.168.30.130"; Mask = "255.255.255.0"; GW = "192.168.30.120" }
    )}
}

foreach ($ovaFile in $ovaFiles) {
    $vmName = $ovaFile.BaseName
    $ovaPath = $ovaFile.FullName
    $vmPath = "$vmFolder\$vmName"
    
    Write-Host "--- $vmName ---" -ForegroundColor Yellow

    if (Test-Path $vmPath) {
        Write-Host "[SKIP] Déjà présente" -ForegroundColor Yellow
        continue
    }

    Write-Host "Déploiement... $ovaPath" -ForegroundColor Cyan
    
    # Exécuter ovftool
    & $ovftool --machineOutput --X:logLevel=verbose --name=$vmName --maxVirtualHardwareVersion=21 --acceptAllEulas --allowExtraConfig "$ovaPath" "$vmFolder" | Out-Null
    
    if (Test-Path "$vmPath\$vmName.vmx") {
        Write-Host "[ok] Importée" -ForegroundColor Green
        
        $succes = Add-VMToInventory -VMXPath "$vmPath\$vmName.vmx" -DisplayName $vmName

    } else {
        Write-Host "[ERREUR] Échouée" -ForegroundColor Red
        continue
    }

    # Configurer les cartes réseau
    if ($vmConfigs.ContainsKey($vmName)) {
        $vmxPath = "$vmPath\$vmName.vmx"
        $vmxContent = Get-Content $vmxPath -Raw
        
        foreach ($nic in $vmConfigs[$vmName].NICs) {
            $nicConfig = @"

ethernet$($nic.Idx).present = "TRUE"
ethernet$($nic.Idx).connectionType = "bridged"
ethernet$($nic.Idx).networkName = "VMnet$($nic.VMnet)"
ethernet$($nic.Idx).addressType = "static"
ethernet$($nic.Idx).ip = "$($nic.IP)"
ethernet$($nic.Idx).subnet = "$($nic.Mask)"
ethernet$($nic.Idx).gateway = "$($nic.GW)"
ethernet$($nic.Idx).dnsServer = "8.8.8.8"
"@
            $vmxContent += $nicConfig
        }
        
        Set-Content -Path $vmxPath -Value $vmxContent
        Write-Host "[ok] Réseau configuré" -ForegroundColor Green
    }
    
}

Write-Host "`n=== Terminé ===" -ForegroundColor Green
