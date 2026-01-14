[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$RootPath,

    [string]$SigntoolPath = "signtool",

    [string]$TimestampUrl = "http://timestamp.digicert.com",

    [string]$Description = "Signed application",
    [string]$DescriptionUrl = "https://example.com",

    [string]$CertThumbprint,
    [string]$CertSubjectName,

    [string]$PfxPath,
    [string]$PfxPassword,

    [string]$TrustedSigningDlibPath,
    [string]$TrustedSigningMetadataPath,

    [switch]$IncludeExtensionlessPE,
    [switch]$ForceResignAllSigned,
    [string[]]$ResignIfPublisherMatches = @("Microsoft"),
    [switch]$SkipSignedByOtherPublishers = $true,
    [switch]$SignCatalogFilesToo,

    # Parallelism: works in PS5.1 via Jobs. 1 = sequential
    [int]$Parallelism = 1,

    [string]$ReportPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsPeFile {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] 2
            $read = $fs.Read($buf, 0, 2)
            if ($read -ne 2) { return $false }
            return ($buf[0] -eq 0x4D -and $buf[1] -eq 0x5A) # "MZ"
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Get-PublisherNameFromSignature {
    param($Sig)
    if ($null -eq $Sig -or $null -eq $Sig.SignerCertificate) { return "" }
    $subject = $Sig.SignerCertificate.Subject
    if ($subject -match 'CN=([^,]+)') { return $Matches[1].Trim() }
    return $subject
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
    param([string]$Path, $BeforeSig)

    if ($ForceResignAllSigned) { return @{ DoSign=$true; Reason="ForceResignAllSigned" } }

    if (-not $BeforeSig.HasSignature) {
        return @{ DoSign=$true; Reason="Unsigned" }
    }

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

function Find-Signtool {
    param([string]$Candidate)

    $cmd = Get-Command $Candidate -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }

    $kits = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin",
        "${env:ProgramFiles(x86)}\Windows Kits\11\bin",
        "$env:ProgramFiles\Windows Kits\11\bin"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($k in $kits) {
        $hit = Get-ChildItem -Path $k -Recurse -Filter "signtool.exe" -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    throw "signtool.exe not found. Install Windows SDK or provide -SigntoolPath."
}

function Find-AzureDlib {
    if ($TrustedSigningDlibPath -and (Test-Path $TrustedSigningDlibPath)) { return $TrustedSigningDlibPath }

    $envCandidates = @(
        $env:TRUSTED_SIGNING_DLIB,
        $env:AZURE_TRUSTED_SIGNING_DLIB,
        $env:AZURE_CODESIGNING_DLIB,
        $env:AZURE_CODE_SIGNING_DLIB
    ) | Where-Object { $_ -and $_.Trim() -ne "" }

    foreach ($c in $envCandidates) { if (Test-Path $c) { return $c } }

    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
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

    foreach ($c in $envCandidates) { if (Test-Path $c) { return $c } }
    return ""
}

function Invoke-SignTool {
    param(
        [string]$Signtool,
        [string]$TargetPath,
        [string]$Dlib,
        [string]$Metadata,
        [bool]$UseTrustedSigning
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

    if ($UseTrustedSigning -and $Dlib -and $Metadata) {
        $args += @("/dlib", $Dlib, "/dmdf", $Metadata)
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

# -----------------------------
# Validate & discover
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
    Write-Host "Azure Trusted Signing not detected (dlib+metadata not both available). Using local cert / PFX if provided."
}

if (-not $usingTrustedSigning) {
    if (-not $PfxPath -and -not $CertThumbprint -and -not $CertSubjectName) {
        throw "Specify signing identity: -PfxPath OR -CertThumbprint OR -CertSubjectName (or provide Trusted Signing dlib+metadata)."
    }
    if ($PfxPath -and -not (Test-Path $PfxPath)) { throw "PfxPath not found: $PfxPath" }
}

# -----------------------------
# Collect signable files
# -----------------------------
$exts = @(".exe",".dll",".sys",".msi",".msp",".cab",".ocx",".appx",".msix")
if ($SignCatalogFilesToo) { $exts += ".cat" }

$files = @(
    Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $ext = $_.Extension.ToLowerInvariant()
        if ($exts -contains $ext) { $true }
        elseif ($IncludeExtensionlessPE -and $ext -eq "" -and (Test-IsPeFile -Path $_.FullName)) { $true }
        else { $false }
    }
)

if ($files.Count -eq 0) {
    Write-Host "No signable files found under: $RootPath"
    exit 0
}

Write-Host "Found $($files.Count) signable files."

# -----------------------------
# Report
# -----------------------------
if (-not $ReportPath) { $ReportPath = $RootPath }
if (-not (Test-Path $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath | Out-Null }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvReport = Join-Path $ReportPath "sign-report-$stamp.csv"
$jsonReport = Join-Path $ReportPath "sign-report-$stamp.json"

function Process-One {
    param($File)

    $path = $File.FullName
    $before = Get-SignatureInfo -Path $path
    $decision = Should-SignFile -Path $path -BeforeSig $before

    $action = if ($decision.DoSign) { "Sign" } else { "Skip" }
    $err = ""
    $exit = $null

    if ($decision.DoSign) {
        try {
            $exit = Invoke-SignTool -Signtool $Signtool -TargetPath $path -Dlib $azureDlib -Metadata $azureMetadata -UseTrustedSigning $usingTrustedSigning
            if ($exit -ne 0) { throw "signtool exit code $exit" }
        } catch {
            $err = $_.Exception.Message
        }
    }

    $after = Get-SignatureInfo -Path $path

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
# Execute (sequential or jobs)
# -----------------------------
$results = @()

if ($Parallelism -le 1) {
    foreach ($f in $files) {
        $results += Process-One -File $f
    }
} else {
    # PS5.1-friendly parallelism via jobs
    $throttle = $Parallelism
    $queue = New-Object System.Collections.Generic.Queue[object]
    $files | ForEach-Object { $queue.Enqueue($_) }

    $jobs = @()

    while ($queue.Count -gt 0 -or $jobs.Count -gt 0) {
        while ($queue.Count -gt 0 -and $jobs.Count -lt $throttle) {
            $file = $queue.Dequeue()

            # Start job with necessary values copied in
            $jobs += Start-Job -ScriptBlock {
                param($file, $RootPath, $Signtool, $azureDlib, $azureMetadata, $usingTrustedSigning, $TimestampUrl, $Description, $DescriptionUrl,
                      $CertThumbprint, $CertSubjectName, $PfxPath, $PfxPassword, $ForceResignAllSigned, $ResignIfPublisherMatches, $SkipSignedByOtherPublishers)

                Set-StrictMode -Version Latest
                $ErrorActionPreference = "Stop"

                function Get-PublisherNameFromSignature { param($Sig)
                    if ($null -eq $Sig -or $null -eq $Sig.SignerCertificate) { return "" }
                    $subject = $Sig.SignerCertificate.Subject
                    if ($subject -match 'CN=([^,]+)') { return $Matches[1].Trim() }
                    return $subject
                }
                function Get-SignatureInfo { param([string]$Path)
                    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
                    $pub = Get-PublisherNameFromSignature $sig
                    [pscustomobject]@{
                        Status        = if ($sig) { [string]$sig.Status } else { "Unknown" }
                        StatusMessage = if ($sig) { [string]$sig.StatusMessage } else { "" }
                        Publisher     = $pub
                        Thumbprint    = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { "" }
                        HasSignature  = if ($sig -and $sig.SignerCertificate) { $true } else { $false }
                    }
                }
                function Should-SignFile { param([string]$Path, $BeforeSig)
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
                        if ($SkipSignedByOtherPublishers) { return @{ DoSign=$false; Reason="Signed by other publisher; skipped" } }
                        return @{ DoSign=$true; Reason="Signed by other publisher; resign allowed by config" }
                    }
                    return @{ DoSign=$true; Reason="Signature not valid ($($BeforeSig.Status))" }
                }
                function Invoke-SignTool { param([string]$TargetPath)
                    $args = @("sign","/v","/fd","SHA256","/tr",$TimestampUrl,"/td","SHA256","/d",$Description,"/du",$DescriptionUrl)

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

                $path = $file.FullName
                $before = Get-SignatureInfo -Path $path
                $decision = Should-SignFile -Path $path -BeforeSig $before

                $action = if ($decision.DoSign) { "Sign" } else { "Skip" }
                $err = ""

                if ($decision.DoSign) {
                    try {
                        $exit = Invoke-SignTool -TargetPath $path
                        if ($exit -ne 0) { throw "signtool exit code $exit" }
                    } catch {
                        $err = $_.Exception.Message
                    }
                }

                $after = Get-SignatureInfo -Path $path

                [pscustomobject]@{
                    Path                 = $path
                    Extension            = $file.Extension
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
            } -ArgumentList @(
                $file, $RootPath, $Signtool, $azureDlib, $azureMetadata, $usingTrustedSigning, $TimestampUrl, $Description, $DescriptionUrl,
                $CertThumbprint, $CertSubjectName, $PfxPath, $PfxPassword, $ForceResignAllSigned, $ResignIfPublisherMatches, $SkipSignedByOtherPublishers
            )
        }

        # collect completed jobs
        $done = $jobs | Where-Object { $_.State -ne 'Running' }
        foreach ($j in $done) {
            $results += Receive-Job $j -ErrorAction SilentlyContinue
            Remove-Job $j -Force | Out-Null
        }
        $jobs = $jobs | Where-Object { $_.State -eq 'Running' }

        Start-Sleep -Milliseconds 100
    }
}

# -----------------------------
# Save report + summary
# -----------------------------
$final = $results | Sort-Object Path
$final | Export-Csv -Path $csvReport -NoTypeInformation -Encoding UTF8
$final | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonReport -Encoding UTF8

$failed  = @($final | Where-Object { $_.Action -eq "Sign" -and $_.Error -and $_.Error.Trim() -ne "" })
$signed  = @($final | Where-Object { $_.Action -eq "Sign" -and (-not $_.Error -or $_.Error.Trim() -eq "") })
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
