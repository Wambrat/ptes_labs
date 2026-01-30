# deploy-3-networks.ps1 - Créer 3 réseaux et déployer les VMs
# Exécuter en admin

function Find-VMwarePaths {
    <#
    .SYNOPSIS
    Trouve les emplacements de VMware Workstation et des outils requis
    .DESCRIPTION
    Cherche les fichiers requis et retourne le chemin de base SEULEMENT si tous les outils sont trouvés:
    - vnetlib.exe
    - ovftool.exe
    - vmnetdhcp.conf
    Sinon, quitte le script.
    #>
    
    $vmwarePaths = @{
        vnetlib     = $null
        ovftool     = $null
        vmwarePath  = $null
    }
    
    # Chercher les répertoires VMware dans Program Files et Program Files (x86)
    $searchPaths = @(
        "C:\Program Files\VMware",
        "C:\Program Files (x86)\VMware"
    )
    
    Write-Host "Recherche des installations VMware..." -ForegroundColor Cyan
    
    # Chercher vnetlib.exe et ovftool.exe
    foreach ($basePath in $searchPaths) {
        if (Test-Path $basePath) {
            # Chercher vnetlib.exe
            if (-not $vmwarePaths.vnetlib) {
                $vnetlib = Get-ChildItem -Path $basePath -Filter "vnetlib.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($vnetlib) {
                    $vmwarePaths.vnetlib = $vnetlib.FullName
                    Write-Host "[ok] vnetlib trouvé: $($vmwarePaths.vnetlib)" -ForegroundColor Green
                }
            }
            
            # Chercher ovftool.exe
            if (-not $vmwarePaths.ovftool) {
                $ovftool = Get-ChildItem -Path $basePath -Filter "ovftool.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($ovftool) {
                    $vmwarePaths.ovftool = $ovftool.FullName
                    Write-Host "[ok] ovftool trouvé: $($vmwarePaths.ovftool)" -ForegroundColor Green
                }
            }
        }
    }
    
    # Récupérer le répertoire VMware principal
    if ($vmwarePaths.vnetlib) {
        $vmwarePaths.vmwarePath = Split-Path -Parent $vmwarePaths.vnetlib

        # verifier que les deux autres outils sont dans le même répertoire parent
        if (-not ($vmwarePaths.ovftool -like "$($vmwarePaths.vmwarePath)*")) {
            $vmwarePaths.vmwarePath = $Null
        }
    }
    
    # Vérifier que TOUS les outils essentiels sont trouvés
    $missingTools = @()
    
    if (-not $vmwarePaths.vnetlib) {
        $missingTools += "vnetlib.exe"
    }
    if (-not $vmwarePaths.ovftool) {
        $missingTools += "ovftool.exe"
    }
    
    if ($missingTools.Count -gt 0) {
        Write-Host "`n[ERREUR CRITIQUE] Outils manquants:" -ForegroundColor Red
        foreach ($tool in $missingTools) {
            Write-Host "  - $tool" -ForegroundColor Red
        }
        Write-Host "`nVeuillez vérifier que VMware Workstation est correctement installé." -ForegroundColor Yellow
        Write-Host "Chemins attendus:" -ForegroundColor Yellow
        Write-Host "  - C:\Program Files\VMware\" -ForegroundColor Yellow
        Write-Host "  - C:\Program Files (x86)\VMware\" -ForegroundColor Yellow
        throw "Outils VMware manquants. Abandon du script."
    }
    
    Write-Host "`n[OK] Tous les outils VMware trouvés avec succès!" -ForegroundColor Green
    return $vmwarePaths
}


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

function Get-AvailableVMnets {
    <#
    .SYNOPSIS
    Détecte ou réutilise les VMnets configurés pour les labs
    .DESCRIPTION
    Utilise ipconfig pour chercher les interfaces VMware existantes et les subnets des labs.
    Si les 3 subnets des labs existent, les réutilise. Sinon, trouve les 3 premiers VMnets libres.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$vnetlibPath
    )
    
    # Subnets des labs à chercher
    $labSubnets = @{
        "192.168.10" = 0   # R1
        "192.168.20" = 0   # R2
        "192.168.30" = 0   # R3
    }
    
    # Récupérer les interfaces réseau avec Get-NetIPAddress
    Write-Host "Recherche des interfaces VMware..." -ForegroundColor Cyan
    
    $netInterfaces = Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength
    $foundVmnets = @{}
    $existingVmnets = @()
    
    # Parser les interfaces pour trouver les VMnets
    foreach ($interface in $netInterfaces) {
        # Chercher les adaptateurs VMnet
        if ($interface.InterfaceAlias -match "VMware Network Adapter VMnet(\d+)") {
            $vmnetNum = [int]$matches[1]
            $existingVmnets += $vmnetNum
            
            # Extraire le subnet de l'adresse IP
            $ipParts = $interface.IPAddress -split '\.'
            $ipPrefix = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])"
            
            # Vérifier si ce subnet correspond à l'un de nos labs
            foreach ($subnet in $labSubnets.Keys) {
                if ($ipPrefix -eq $subnet) {
                    $foundVmnets[$subnet] = $vmnetNum
                    Write-Host "[RÉUTILISATION] Subnet $subnet trouvé sur vmnet$vmnetNum (IP: $($interface.IPAddress))" -ForegroundColor Green
                }
            }
        }
    }
    
    # Si les 3 subnets des labs sont trouvés, les utiliser
    if ($foundVmnets.Count -eq 3) {
        $reusedVmnets = @($foundVmnets["192.168.10"], $foundVmnets["192.168.20"], $foundVmnets["192.168.30"])
        Write-Host "VMnets à utiliser pour les labs: $($reusedVmnets -join ', ')" -ForegroundColor Cyan
        return $reusedVmnets
    }
    
    # Sinon, chercher les 3 premiers VMnets libres
    Write-Host "Subnets des labs non trouvés, création de nouveaux VMnets..." -ForegroundColor Yellow
    
    # Trouver les 3 prochains vmnets libres (en commençant par 2, puis 3, 4, 5...)
    $availableVmnets = @()
    $vmnetNum = 2
    while ($availableVmnets.Count -lt 3) {
        if ($vmnetNum -notin $existingVmnets) {
            $availableVmnets += $vmnetNum
        }
        $vmnetNum++
    }
    
    Write-Host "VMnets existants trouvés: $($existingVmnets -join ', ')" -ForegroundColor Cyan
    Write-Host "VMnets à utiliser pour les labs: $($availableVmnets -join ', ')" -ForegroundColor Cyan
    
    return $availableVmnets
}

# lancer la fonction dans commons_functions.psm1
Import-Module "$PSScriptRoot\commons_functions.psm1"

Write-Host "=== Vérification des fichiers OVA des labs ===" -ForegroundColor Cyan
$success = Ensure-VmsOvas
if (-not $success) {
    Write-Host "Impossible de vérifier ou d'extraire les fichiers OVA. Abandon." -ForegroundColor Red
    exit 1
}

# Vérifier admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERREUR: Exécuter en tant qu'administrateur!" -ForegroundColor Red
    exit 1
}

# Trouver les chemins VMware
Write-Host "`n=== Détection des outils VMware ===" -ForegroundColor Cyan
$vmwarePaths = Find-VMwarePaths

# Détecter les VMnets disponibles dynamiquement
Write-Host "`n=== Détection des VMnets disponibles ===" -ForegroundColor Cyan
$availableVmnets = Get-AvailableVMnets -vnetlibPath $vmwarePaths.vnetlib

if ($availableVmnets.Count -ne 3) {
    Write-Host "Impossible de détecter ou créer 3 VMnets. Abandon." -ForegroundColor Red
    exit 1
}

# Configuration des 3 réseaux avec VMnets dynamiques
$networks = @(
    @{ Name = "R1"; VMnet = $availableVmnets[0]; Subnet = "192.168.10.0"; Netmask = "255.255.255.0"; Gateway = "192.168.10.130"; AdapterIP = "192.168.10.1" },
    @{ Name = "R2"; VMnet = $availableVmnets[1]; Subnet = "192.168.20.0"; Netmask = "255.255.255.0"; Gateway = "192.168.20.110"; AdapterIP = "192.168.20.1" },
    @{ Name = "R3"; VMnet = $availableVmnets[2]; Subnet = "192.168.30.0"; Netmask = "255.255.255.0"; Gateway = "192.168.30.120"; AdapterIP = "192.168.30.1" }
)

# Créer un mapping pour les configurations VM (ancien vmnet -> nouveau vmnet)
$vnetMapping = @{
    2 = $availableVmnets[0]
    3 = $availableVmnets[1]
    4 = $availableVmnets[2]
}

Write-Host "=== Configuration de 3 réseaux VMware ===" -ForegroundColor Cyan

$success = $true
foreach ($net in $networks) {
    try {
        Write-Host "`n--- $($net.Name) (VMnet$($net.VMnet): $($net.Subnet)/$($net.Netmask)) ---" -ForegroundColor Yellow
        
        # Vérifier si l'adaptateur existe déjà
        $adapter = Get-NetAdapter | Where-Object { $_.Name -like "*VMnet$($net.VMnet)*" }
        
        if ($adapter) {
            Write-Host "[SKIP] Déjà créé" -ForegroundColor Yellow
            continue
        }
        
        & $vmwarePaths.vnetlib -- add adapter "vmnet$($net.VMnet)" | Out-Null
        & $vmwarePaths.vnetlib -- set vnet "vmnet$($net.VMnet)" addr $net.Subnet | Out-Null
        & $vmwarePaths.vnetlib -- set vnet "vmnet$($net.VMnet)" mask $net.Netmask | Out-Null
        & $vmwarePaths.vnetlib -- add dhcp "vmnet$($net.VMnet)" | Out-Null
        Write-Host "[ok] Adaptateur configuré" -ForegroundColor Green
        Start-Sleep -Seconds 3
        netsh interface ip set address "VMware Network Adapter VMnet$($net.VMnet)" static $net.AdapterIP $net.Netmask | Out-Null
        Write-Host "[ok] IP $($net.AdapterIP)/24 configurée" -ForegroundColor Green
    } catch{
        $success = $false
        break
    }
}

if (-not $success) {
    Write-Host "Échec de la configuration des réseaux. Abandon." -ForegroundColor Red
    exit 1
}

# ===== DÉPLOIEMENT DES VMS =====
Write-Host "`n`n=== Déploiement des VMs ===" -ForegroundColor Cyan

$ovasFolder = "$PSScriptRoot\vms_ovas"

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
        $vmFolder = "$env:USERPROFILE\Vms\LabVms"
    }
} else {
    Write-Host "Fichier preferences.ini non trouvé. Utilisation par défaut..." -ForegroundColor Yellow
    $vmFolder = "$env:USERPROFILE\Vms\LabVms"
}

# Vérifier ovftool (déjà trouvé via Find-VMwarePaths)
$ovftool = $vmwarePaths.ovftool

if (-not (Test-Path $vmFolder)) {
    New-Item -ItemType Directory -Path $vmFolder -Force | Out-Null
}

if (-not (Test-Path $ovasFolder)) {
    Write-Host "Dossier vms_ovas n'existe pas. Arret du script" -ForegroundColor Yellow
    exit 0
}

$ovaFiles = Get-ChildItem -Path $ovasFolder -Filter "*.ova" -ErrorAction SilentlyContinue

if ($ovaFiles.Count -eq 0) {
    Write-Host "Aucun fichier OVA trouvé dans $ovasFolder" -ForegroundColor Yellow
    exit 0
}

Write-Host "Trouvé $($ovaFiles.Count) OVA(s) à déployer`n" -ForegroundColor Green

# Configuration des VMs (mapping OVA -> config réseau avec VMnets dynamiques)
$vmConfigs = @{
    "TLS-DC-01" = @{ NICs = @(
        @{ Idx = 1; VMnet = $vnetMapping[2] },
        @{ Idx = 2; VMnet = $vnetMapping[3] }
    )}
    "SRV-WEB-01" = @{ NICs = @(
        @{ Idx = 0; VMnet = $vnetMapping[1]; PCISlotNumber = "18"; ConnectionType = "nat" },
        @{ Idx = 1; VMnet = $vnetMapping[2]; PCISlotNumber = "19"; ConnectionType = "bridge" }
    )}
    "SRV-WINDOWS-01" = @{ NICs = @(
        @{ Idx = 1; VMnet = $vnetMapping[2] }
    )}
    "GRE-DC-01" = @{ NICs = @(
        @{ Idx = 1; VMnet = $vnetMapping[3] },
        @{ Idx = 2; VMnet = $vnetMapping[4] }
    )}
    "SRV-WINDOWS-02" = @{ NICs = @(
        @{ Idx = 1; VMnet = $vnetMapping[4] }
    )}
}

foreach ($ovaFile in $ovaFiles) {
    $vmName = $ovaFile.BaseName
    $ovaPath = $ovaFile.FullName
    $vmPath = "$vmFolder\$vmName"
    
    Write-Host "--- $vmName ---" -ForegroundColor Yellow

    if ((Test-Path $vmPath) -or (-not ($vmName -eq "SRV-WEB-01"))) {
        Write-Host "[SKIP] Déjà présente" -ForegroundColor Yellow
        continue
    }

    Write-Host "Déploiement ..." -ForegroundColor Cyan
    
    # Exécuter ovftool
    & $ovftool --machineOutput --X:logLevel=verbose --name=$vmName --maxVirtualHardwareVersion=21 --acceptAllEulas --allowExtraConfig "$ovaPath" "$vmFolder" | Out-Null
    
    if (Test-Path "$vmPath\$vmName.vmx") {
        Write-Host "[ok] Importée" -ForegroundColor Green
        
        $success = Add-VMToInventory -VMXPath "$vmPath\$vmName.vmx" -DisplayName $vmName

    } else {
        Write-Host "[ERREUR] Échouée" -ForegroundColor Red
        continue
    }

    # Configurer les cartes réseau
    if ($vmConfigs.ContainsKey($vmName)) {
        $vmxPath = "$vmPath\$vmName.vmx"
        $vmxContent = Get-Content $vmxPath -Raw
        
        # Remplacer ethernet0 bridged en nat s'il existe
        foreach ($nic in $vmConfigs[$vmName].NICs) {
            $nicConfig = ""

            if ($nic.Idx -eq 0) {
                $vmxContent = $vmxContent -replace 'ethernet0\.connectionType\s*=\s*"bridged"', "ethernet0.connectionType = `"$($nic.ConnectionType)`""
                $vmsxContent = $vmxContent -replace 'ethernet0\.virtualDev\s*=\s*"vmxnet3"', 'ethernet0.virtualDev = "e1000e"'
                $nicConfig += @"

ethernet$($nic.Idx).networkName = "VMnet$($nic.VMnet)"
ethernet$($nic.Idx).pciSlotNumber = "$($nic.PCISlotNumber)"

"@
            } else {
                $nicConfig +=@"
ethernet$($nic.Idx).present = "TRUE"
ethernet$($nic.Idx).connectionType = "$($nic.ConnectionType)"
ethernet$($nic.Idx).startConnected = "TRUE"
ethernet$($nic.Idx).addressType = "generated"
ethernet$($nic.Idx).virtualDev = "e1000e"
ethernet$($nic.Idx).networkName = "VMnet$($nic.VMnet)"
ethernet$($nic.Idx).pciSlotNumber = "$($nic.PCISlotNumber)"
"@
            }
            
            $vmxContent += $nicConfig
        }
        
        Set-Content -Path $vmxPath -Value $vmxContent
        Write-Host "[ok] Réseau configuré" -ForegroundColor Green
    }
    
}

Write-Host "`n=== Terminé ===" -ForegroundColor Green
