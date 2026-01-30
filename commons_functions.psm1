# recupération des ovas vms par une url "https://fyc2026.duckdns.org/vms_ovas.zip"

function Get-VmsOvas {
    param (
        [string]$url = "https://fyc2026.duckdns.org/vms_ovas.zip",
        [string]$destinationPath = "$PSScriptRoot\vms_ovas.zip"
    )

    # Télécharger le fichier zip
    $res = Invoke-WebRequest -Uri $url -OutFile $destinationPath
    if ($res.StatusCode -ne 200) {
        throw "Erreur lors du téléchargement du fichier: $($res.StatusCode)"
    }

    return $res
}

function Extract-VmsOvas {
    param (
        [string]$zipPath = "$PSScriptRoot\vms_ovas.zip",
        [string]$extractPath = "$PSScriptRoot"
    )

    # Créer le répertoire de destination s'il n'existe pas
    if (-not (Test-Path -Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath | Out-Null
    }

    # Extraire le fichier zip
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

    return $extractPath
}

# checker que le dossier vms_ovas existe et contient des fichiers
    # sinon lancer le téléchargement et l'extraction
    # si oui
        # regarde bien qu'on est tout les ova soit "SRV-WINDOWS-01.ova", "SRV-WINDOWS-02.ova", "TLS-DC-01.ova", "SRV-WEB-01.ova", "GRE-DC-01.ova"
        # sinon supprimer tout les fichiers du dossier et relancer le téléchargement et l'extraction

function Ensure-VmsOvas {
    param (
        [string]$vmsOvasPath = "$PSScriptRoot\vms_ovas"
    )

    $requiredOvas = @(
        "SRV-WINDOWS-01.ova",
        "SRV-WINDOWS-02.ova",
        "TLS-DC-01.ova",
        "SRV-WEB-01.ova",
        "GRB-DC-01.ova"
    )
    try {
        
        # Vérifier si le dossier existe et contient les fichiers
        if (Test-Path -Path $vmsOvasPath) {
            $ovaFiles = @(Get-ChildItem -Path $vmsOvasPath -Filter "*.ova" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
            
            # Vérifier que tous les fichiers requis sont présents
            $allPresent = $true
            foreach ($requiredOva in $requiredOvas) {
                if ($requiredOva -notin $ovaFiles) {
                    $allPresent = $false
                    break
                }
            }

            # Si tous les fichiers sont présents, retourner le chemin
            if ($allPresent) {
                Write-Host "Les fichiers OVA sont déjà présents." -ForegroundColor Green
                return $True
            }

            Write-Host "Suppression des fichiers OVA incomplets..." -ForegroundColor Yellow
            #Remove-Item -Path $vmsOvasPath -Recurse -Force
        }

        if (-not (Test-Path -Path "$vmsOvasPath.zip")) {
            Write-Host "Téléchargement des fichiers OVA..." -ForegroundColor Yellow
            Get-VmsOvas
        } else {
            Write-Host "Fichier zip des OVA déjà téléchargé." -ForegroundColor Green
        }
        
        Write-Host "Extraction des fichiers OVA..." -ForegroundColor Yellow
        Extract-VmsOvas

        return $True
    } catch {
        Write-Host "Une erreur est survenue: $_" -ForegroundColor Red
        return $False
    }
}  