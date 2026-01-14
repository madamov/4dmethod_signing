<#
Sign-All.ps1
Recursively signs “everything signable” in a folder + subfolders, with all enhancements:
✅ skips already-signed files (default)
✅ can re-sign only if signed by Microsoft (or any allowed publisher list)
✅ skips files signed by “other” publishers by default (safe)
✅ Azure Trusted Signing auto-detection (dlib + metadata via params/env/typical install paths)
✅ parallel signing (PowerShell 7+)
✅ signing report (CSV + JSON) with before/after signature status, action, errors

REQUIRES: signtool.exe available (Windows SDK / VS) OR provide -SigntoolPath.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$RootPath,

    # If signtool isn't in PATH, provide full path
    [string]$SigntoolPath = "signtool",

    # Timestamp server (RFC3161)
    [string]$TimestampUrl = "http://timestamp.digicert.com",

    # Friendly description for Win32 PE signatures
    [string]$Description = "Signed application",
    [string]$DescriptionUrl = "https://example.com",

    # Cert selection (use either thumbprint OR subject)
    [string]$CertThumbprint,
    [string]$CertSubjectName,

    # If using PFX directly (optional)
    [string]$PfxPath,
    [string]$PfxPassword, # pass via secret; avoid hardcoding

    # Azure Trusted Signing (signtool + dlib + metadata.json)
    [string]$TrustedSigningDlibPath,
    [string]$TrustedSigningMetadataPath,

    # Controls
    [switch]$IncludeExtensionlessPE,     # also sign extensionless PE files (MZ header)
    [switch]$ForceResignAllSigned,       # override everything signed (dangerous)
    [string[]]$ResignIfPublisherMatches = @("Microsoft"),  # re-sign only if signed by these publishers
    [switch]$SkipSignedByOtherPublishers = $true,          # default: skip non-Microsoft signed files
    [switch]$SignCatalogFilesToo,        # enables .cat if present in tree
    [int]$Parallelism = 0,               # 0 = auto (PS7 uses CPU-1), 1 = no parallel
    [string]$ReportPath = ""             # folder for reports; default = RootPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------
# Helpers
# -----------------------------
function Test-IsPeFile {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] 2
            $read = $fs.Read($buf, 0, 2)
            if ($read -ne 2) { return $false }
            # "MZ"
            return ($buf[0] -eq 0x4D -and $buf[1] -eq 0x5A)
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Get-PublisherNameFromSignature {
    param($Sig)
    # $Sig.SignerCertificate.Subject often contains CN=Publisher
    if ($null -eq $Sig -or $null -eq $Sig.SignerCertificate) { return "" }
    $subject = $Sig.SignerCertificate.Subject
    # Try to extract CN=...
    if ($subject -match 'CN=([^,]+)') { return $Matches[1].Trim() }
    return $subject
}

function Find-Signtool {
    param([string]$Candidate)
    if ($Candidate -and (Get-Command $Candidate -ErrorAction SilentlyContinue)) { return $Candidate }

    # Try common Windows SDK locations
    $kits = @(
        "$env:ProgramFiles(x86)\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin",
        "$env:ProgramFiles(x86)\Windows Kits\11\bin",
        "$env:ProgramFiles\Windows Kits\11\bin"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($k in $kits) {
        # pick the newest signtool from any versioned subfolder
        $hit = Get-ChildItem -Path $k -Recurse -Filter "signtool.exe" -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    throw "signtool.exe not found. Install Windows SDK (SignTool) or provide -SigntoolPath."
}

function Find-AzureDlib {
    # If user explicitly provided it, honor that
    if ($TrustedSigningDlibPath -and (Test-Path $TrustedSigningDlibPath)) { return $TrustedSigningDlibPath }

    # Env vars commonly used in CI setups (support several names)
    $envCandidates = @(
        $env:TRUSTED_SIGNING_DLIB,
        $env:AZURE_TRUSTED_SIGNING_DLIB,
        $env:AZURE_CODESIGNING_DLIB,
        $env:AZURE_CODE_SIGNING_DLIB
    ) | Where-Object { $_ -and $_.Trim() -ne "" }

    foreach ($c in $envCandidates) {
        if (Test-Path $c) { return $c }
    }

    # Typical install hints: Azure.CodeSigning.Dlib.dll might live near tools/packages
    $roots = @(
        $env:ProgramFiles,
        $env:ProgramFiles(x86),
        $env:LOCALAPPDATA,
        $env:USERPROFILE
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($r in $roots) {
        $hit = Get-ChildItem -Path $r -Recurse -Filter "Azure.CodeSigning.Dlib.dll" -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    return ""
}

function Find-AzureMetadata {
    if ($TrustedSigningMetadataPath -and (Test-Path $TrustedSigningMetadataPath)) { return $TrustedSigningMetadataPath }

    $envCandidates = @(
        $env:TRUSTED_SIGNING_METADATA,
        $env:AZURE_TRUSTED_SIGNING_METADATA,
        $env:AZURE_CODESIGNING_METADATA,
        $env:AZURE_CODE_SIGNING_METADATA
    ) | Where-Object { $_ -and $_.Trim() -ne "" }

    foreach ($c in $envCandidates) {
        if (Test-Path $c) { return $c }
    }

    return ""
}

function Get-SignatureInfo {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    $pub = Get-PublisherNameFromSignature $sig
    [pscustomobject]@{
        Status          = if ($sig) { [string]$sig.Status } else { "Unknown" }
        StatusMessage   = if ($sig) { [string]$sig.StatusMessage } else { "" }
        Publisher       = $pub
        Thumbprint      = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { "" }
        HasSignature    = if ($sig -and $sig.SignerCertificate) { $true } else { $false }
    }
}

function Should-SignFile {
    param(
        [string]$Path,
        $BeforeSig
    )

    if ($ForceResignAllSigned) { return @{ DoSign=$true; Reason="ForceResignAllSigned" } }

    if (-not $BeforeSig.HasSignature) {
        return @{ DoSign=$true; Reason="Unsigned" }
    }

    # Signed already:
    if ($BeforeSig.Status -eq "Valid") {
        # If signed by expected cert, skip
        if ($CertThumbprint -and ($BeforeSig.Thumbprint -eq $CertThumbprint)) {
            return @{ DoSign=$false; Reason="Already signed by desired thumbprint" }
        }
        if ($CertSubjectName -and ($BeforeSig.Publisher -like "*$CertSubjectName*")) {
            return @{ DoSign=$false; Reason="Already signed by desired subject/publisher match" }
        }

        # If signed by Microsoft (or other allowed publishers), you may choose to re-sign
        foreach ($p in $ResignIfPublisherMatches) {
            if ($p -and $BeforeSig.Publisher -like "*$p*") {
                return @{ DoSign=$true; Reason="Resign allowed publisher: $p" }
            }
        }

        # Otherwise, by default skip other publishers (safe)
        if ($SkipSignedByOtherPublishers) {
            return @{ DoSign=$false; Reason="Signed by other publisher; skipped" }
        }

        # If not skipping, we sign anyway (overwrites)
        return @{ DoSign=$true; Reason="Signed by other publisher; resign allowed by config" }
    }

    # Invalid/Unknown signatures: re-sign to fix
    return @{ DoSign=$true; Reason="Signature not valid ($($BeforeSig.Status))" }
}

function Invoke-SignTool {
    param(
        [string]$Signtool,
        [string]$TargetPath,
        [string]$Dlib,
        [string]$Metadata
    )

    $args = @(
        "sign",
        "/v",
        "/fd", "SHA256",
        "/tr", $TimestampUrl,
        "/td", "SHA256",
        "/d", $Description,
        "/du", $DescriptionUrl
    )

    # Prefer Azure Trusted Signing if dlib+metadata are found
    if ($Dlib -and $Metadata) {
        $args += @("/dlib", $Dlib, "/dmdf", $Metadata)
        # Note: with Trusted Signing, cert selection is typically in metadata.
    } else {
        # Local cert store or PFX
        if ($PfxPath) {
            $args += @("/f", $PfxPath)
            if ($PfxPassword) { $args += @("/p", $PfxPassword) }
        } elseif ($CertThumbprint) {
            $args += @("/sha1", $CertThumbprint)
        } elseif ($CertSubjectName) {
            $args += @("/n", $CertSubjectName)
        } else {
            throw "No signing identity specified. Provide -PfxPath OR -CertThumbprint OR -CertSubjectName, or provide Azure Trusted Signing dlib+metadata."
        }
    }

    $args += "`"$TargetPath`""

    & $Signtool $args
    return $LASTEXITCODE
}

# -----------------------------
# Validate & Discover tool paths
# -----------------------------
if (-not (Test-Path $RootPath)) { throw "RootPath does not exist: $RootPath" }
$RootPath = (Resolve-Path $RootPath).Path

$Signtool = Find-Signtool -Candidate $SigntoolPath

$azureDlib = Find-AzureDlib
$azureMetadata = Find-AzureMetadata
$usingTrustedSigning = ($azureDlib -and $azureMetadata)

if ($usingTrustedSigning) {
    Write-Host "Azure Trusted Signing detected:"
    Write-Host "  dlib:     $azureDlib"
    Write-Host "  metadata: $azureMetadata"
} else {
    Write-Host "Azure Trusted Signing not detected (dlib+metadata not both available). Using local cert selection/PFX if provided."
}

if (-not $usingTrustedSigning) {
    if (-not $PfxPath -and -not $CertThumbprint -and -not $CertSubjectName) {
        throw "Specify signing identity: -PfxPath OR -CertThumbprint OR -CertSubjectName (or provide Trusted Signing dlib+metadata)."
    }
    if ($PfxPath -and -not (Test-Path $PfxPath)) { throw "PfxPath not found: $PfxPath" }
}

# -----------------------------
# Build list of signable files
# -----------------------------
$exts = @(".exe",".dll",".sys",".msi",".msp",".cab",".ocx",".appx",".msix")
if ($SignCatalogFilesToo) { $exts += ".cat" }

$files = Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $ext = $_.Extension.ToLowerInvariant()
    if ($exts -contains $ext) { $_; return }

    # Optionally catch extensionless PE files
    if ($IncludeExtensionlessPE -and ($ext -eq "") -and (Test-IsPeFile -Path $_.FullName)) {
        $_
    }
}

$files = @($files)
if ($files.Count -eq 0) {
    Write-Host "No signable files found under: $RootPath"
    exit 0
}

Write-Host "Found $($files.Count) signable files."

# -----------------------------
# Report setup
# -----------------------------
if (-not $ReportPath) { $ReportPath = $RootPath }
if (-not (Test-Path $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath | Out-Null }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvReport = Join-Path $ReportPath "sign-report-$stamp.csv"
$jsonReport = Join-Path $ReportPath "sign-report-$stamp.json"

$results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

# -----------------------------
# Worker block (supports parallel)
# -----------------------------
$worker = {
    param(
        $File,
        $Signtool,
        $azureDlib,
        $azureMetadata,
        $usingTrustedSigning,
        $TimestampUrl,
        $Description,
        $DescriptionUrl,
        $CertThumbprint,
        $CertSubjectName,
        $PfxPath,
        $PfxPassword,
        $ForceResignAllSigned,
        $ResignIfPublisherMatches,
        $SkipSignedByOtherPublishers
    )

    function Get-PublisherNameFromSignatureLocal {
        param($Sig)
        if ($null -eq $Sig -or $null -eq $Sig.SignerCertificate) { return "" }
        $subject = $Sig.SignerCertificate.Subject
        if ($subject -match 'CN=([^,]+)') { return $Matches[1].Trim() }
        return $subject
    }

    function Get-SignatureInfoLocal {
        param([string]$Path)
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        $pub = Get-PublisherNameFromSignatureLocal $sig
        [pscustomobject]@{
            Status          = if ($sig) { [string]$sig.Status } else { "Unknown" }
            StatusMessage   = if ($sig) { [string]$sig.StatusMessage } else { "" }
            Publisher       = $pub
            Thumbprint      = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { "" }
            HasSignature    = if ($sig -and $sig.SignerCertificate) { $true } else { $false }
        }
    }

    function Should-SignFileLocal {
        param([string]$Path, $BeforeSig)

        if ($ForceResignAllSigned) { return @{ DoSign=$true; Reason="ForceResignAllSigned" } }

        if (-not $BeforeSig.HasSignature) { return @{ DoSign=$true; Reason="Unsigned" } }

        if ($BeforeSig.Status -eq "Valid") {
            if ($CertThumbprint -and ($BeforeSig.Thumbprint -eq $CertThumbprint)) {
                return @{ DoSign=$false; Reason="Already signed by desired thumbprint" }
            }
            if ($CertSubjectName -and ($BeforeSig.Publisher -like "*$CertSubjectName*")) {
                return @{ DoSign=$false; Reason="Already signed by desired subject/publisher match" }
            }

            foreach ($p in $ResignIfPublisherMatches) {
                if ($p -and $BeforeSig.Publisher -like "*$p*") {
                    return @{ DoSign=$true; Reason="Resign allowed publisher: $p" }
                }
            }

            if ($SkipSignedByOtherPublishers) {
                return @{ DoSign=$false; Reason="Signed by other publisher; skipped" }
            }

            return @{ DoSign=$true; Reason="Signed by other publisher; resign allowed by config" }
        }

        return @{ DoSign=$true; Reason="Signature not valid ($($BeforeSig.Status))" }
    }

    function Invoke-SignToolLocal {
        param([string]$TargetPath)

        $args = @(
            "sign",
            "/v",
            "/fd", "SHA256",
            "/tr", $TimestampUrl,
            "/td", "SHA256",
            "/d", $Description,
            "/du", $DescriptionUrl
        )

        if ($usingTrustedSigning -and $azureDlib -and $azureMetadata) {
            $args += @("/dlib", $azureDlib, "/dmdf", $azureMetadata)
        } else {
            if ($PfxPath) {
                $args += @("/f", $PfxPath)
                if ($PfxPassword) { $args += @("/p", $PfxPassword) }
            } elseif ($CertThumbprint) {
                $args += @("/sha1", $CertThumbprint)
            } elseif ($CertSubjectName) {
                $args += @("/n", $CertSubjectName)
            } else {
                throw "No signing identity specified."
            }
        }

        $args += "`"$TargetPath`""
        & $Signtool $args
        return $LASTEXITCODE
    }

    $path = $File.FullName
    $before = Get-SignatureInfoLocal -Path $path
    $decision = Should-SignFileLocal -Path $path -BeforeSig $before

    $action = if ($decision.DoSign) { "Sign" } else { "Skip" }
    $exit = $null
    $err = ""

    if ($decision.DoSign) {
        try {
            $exit = Invoke-SignToolLocal -TargetPath $path
            if ($exit -ne 0) { throw "signtool exit code $exit" }
        } catch {
            $err = $_.Exception.Message
        }
    }

    $after = Get-SignatureInfoLocal -Path $path

    [pscustomobject]@{
        Path                 = $path
        Extension            = $File.Extension
        Action               = $action
        Reason               = $decision.Reason
        SigBeforeStatus      = $before.Status
        SigBeforePublisher   = $before.Publisher
        SigBeforeThumbprint  = $before.Thumbprint
        SigAfterStatus       = $after.Status
        SigAfterPublisher    = $after.Publisher
        SigAfterThumbprint   = $after.Thumbprint
        Error                = $err
    }
}

# -----------------------------
# Run signing (parallel if PS7 and enabled)
# -----------------------------
$useParallel = $false
if ($Parallelism -eq 1) {
    $useParallel = $false
} elseif ($PSVersionTable.PSVersion.Major -ge 7) {
    $useParallel = $true
}

if ($useParallel) {
    if ($Parallelism -le 0) {
        $Parallelism = [Math]::Max(1, [Environment]::ProcessorCount - 1)
    }
    Write-Host "Signing in parallel with throttle: $Parallelism"

    $files | ForEach-Object -Parallel {
        $r = & $using:worker `
            -File $_ `
            -Signtool $using:Signtool `
            -azureDlib $using:azureDlib `
            -azureMetadata $using:azureMetadata `
            -usingTrustedSigning $using:usingTrustedSigning `
            -TimestampUrl $using:TimestampUrl `
            -Description $using:Description `
            -DescriptionUrl $using:DescriptionUrl `
            -CertThumbprint $using:CertThumbprint `
            -CertSubjectName $using:CertSubjectName `
            -PfxPath $using:PfxPath `
            -PfxPassword $using:PfxPassword `
            -ForceResignAllSigned $using:ForceResignAllSigned `
            -ResignIfPublisherMatches $using:ResignIfPublisherMatches `
            -SkipSignedByOtherPublishers $using:SkipSignedByOtherPublishers
        $using:results.Add($r)
    } -ThrottleLimit $Parallelism
} else {
    Write-Host "Signing sequentially (PS7 parallel disabled or not available)."
    foreach ($f in $files) {
        $r = & $worker `
            -File $f `
            -Signtool $Signtool `
            -azureDlib $azureDlib `
            -azureMetadata $azureMetadata `
            -usingTrustedSigning $usingTrustedSigning `
            -TimestampUrl $TimestampUrl `
            -Description $Description `
            -DescriptionUrl $DescriptionUrl `
            -CertThumbprint $CertThumbprint `
            -CertSubjectName $CertSubjectName `
            -PfxPath $PfxPath `
            -PfxPassword $PfxPassword `
            -ForceResignAllSigned $ForceResignAllSigned `
            -ResignIfPublisherMatches $ResignIfPublisherMatches `
            -SkipSignedByOtherPublishers $SkipSignedByOtherPublishers
        $results.Add($r)
    }
}

# -----------------------------
# Save report + summary
# -----------------------------
$final = $results.ToArray() | Sort-Object Path

$final | Export-Csv -Path $csvReport -NoTypeInformation -Encoding UTF8
$final | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonReport -Encoding UTF8

$failed = @($final | Where-Object { $_.Action -eq "Sign" -and $_.Error -and $_.Error.Trim() -ne "" })
$signed = @($final | Where-Object { $_.Action -eq "Sign" -and (-not $_.Error -or $_.Error.Trim() -eq "") })
$skipped = @($final | Where-Object { $_.Action -eq "Skip" })

Write-Host ""
Write-Host "Done."
Write-Host "  Signed : $($signed.Count)"
Write-Host "  Skipped: $($skipped.Count)"
Write-Host "  Failed : $($failed.Count)"
Write-Host "Reports:"
Write-Host "  CSV : $csvReport"
Write-Host "  JSON: $jsonReport"

if ($failed.Count -gt 0) {
    Write-Error "Some files failed to sign. See report for details."
    exit 1
}

exit 0
