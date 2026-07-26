<#
.SYNOPSIS
    Deploy threat-hunting Hunt Cards to Microsoft Sentinel as Scheduled Analytic
    Rules or saved Hunting Queries.

.DESCRIPTION
    Parses a Hunt Card markdown file (or every card in a tactic folder), extracts
    the primary KQL block and the MITRE ATT&CK metadata, and deploys each via the
    ARM templates in this directory. Names artifacts from the Hunt ID so re-runs
    update rather than duplicate.

.PARAMETER ResourceGroup
    Resource group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    Log Analytics / Microsoft Sentinel workspace name.

.PARAMETER HuntCardPath
    Path to a single Hunt Card .md file, or a directory of Hunt Cards.

.PARAMETER Mode
    ScheduledRule (analytic detection) or HuntingQuery (saved hunt). Default: HuntingQuery.

.PARAMETER DryRun
    Print what would be deployed without calling Azure.

.EXAMPLE
    ./Deploy-Hunts.ps1 -ResourceGroup rg-sentinel -WorkspaceName law-sentinel `
        -HuntCardPath ../hunts/impact/shadow-copy-deletion.md -Mode ScheduledRule

.NOTES
    Author: Rizko Febri Rachmayadi
    Requires: Az PowerShell module, Connect-AzAccount, Sentinel Contributor role.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $WorkspaceName,
    [Parameter(Mandatory)] [string] $HuntCardPath,
    [ValidateSet('ScheduledRule', 'HuntingQuery')] [string] $Mode = 'HuntingQuery',
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Map Hunt Card 'Severity if confirmed' to Sentinel severity enum.
function Convert-Severity([string] $raw) {
    switch -Wildcard ($raw.ToLower()) {
        '*critical*' { return 'High' }   # Sentinel has no 'Critical'; map to High
        '*high*'     { return 'High' }
        '*medium*'   { return 'Medium' }
        '*low*'      { return 'Low' }
        default      { return 'Medium' }
    }
}

# Map ATT&CK tactic (slug OR display name, possibly compound 'A / B') -> Sentinel tactic.
# Takes the FIRST tactic when compound, normalizes spacing/hyphens.
function Convert-Tactic([string] $raw) {
    if (-not $raw) { return $null }
    $first = ($raw -split '/')[0].Trim().ToLower() -replace '\s+', '-'
    switch ($first) {
        'initial-access'       { 'InitialAccess' }
        'execution'            { 'Execution' }
        'persistence'          { 'Persistence' }
        'privilege-escalation' { 'PrivilegeEscalation' }
        'defense-evasion'      { 'DefenseEvasion' }
        'credential-access'    { 'CredentialAccess' }
        'discovery'            { 'Discovery' }
        'lateral-movement'     { 'LateralMovement' }
        'collection'           { 'Collection' }
        'command-and-control'  { 'CommandAndControl' }
        'exfiltration'         { 'Exfiltration' }
        'impact'               { 'Impact' }
        default                { $null }
    }
}

# Parse a single Hunt Card: return a PSCustomObject with the fields we deploy.
function Read-HuntCard([string] $path) {
    $md = Get-Content -Raw -Path $path

    # Hunt ID (metadata table row: | **Hunt ID** | TH-XX-000 |)
    $huntId = [regex]::Match($md, '(?im)\|\s*\**\s*Hunt ID\s*\**\s*\|\s*([A-Z0-9\-]+)\s*\|').Groups[1].Value.Trim()
    if (-not $huntId) { $huntId = [IO.Path]::GetFileNameWithoutExtension($path) }

    # Title (first '# Hunt Card — <title>')
    $title = [regex]::Match($md, '(?m)^#\s*Hunt Card\s*[—\-]\s*(.+)$').Groups[1].Value.Trim()
    if (-not $title) { $title = $huntId }

    # Tactic (may be compound like 'Privilege Escalation / Defense Evasion')
    $tacticSlug = [regex]::Match($md, '(?im)\|\s*\**\s*Tactic\s*\**\s*\|\s*([^\|\r\n]+?)\s*\|').Groups[1].Value.Trim()

    # Technique IDs (all Txxxx / Txxxx.xxx mentioned in the metadata block)
    $techniques = @([regex]::Matches($md, '\bT\d{4}(?:\.\d{3})?\b') | ForEach-Object { $_.Value } | Select-Object -Unique)

    # Severity
    $sevRaw = [regex]::Match($md, '(?im)\|\s*\**\s*Severity if confirmed\s*\**\s*\|\s*([^\|\r\n]+?)\s*\|').Groups[1].Value
    $severity = Convert-Severity $sevRaw

    # Primary KQL = first ```kql fenced block
    $kql = [regex]::Match($md, '(?s)```kql\s*(.+?)```').Groups[1].Value.Trim()

    # Description = hypothesis blockquote, flattened
    $descM = [regex]::Match($md, '(?s)##\s*2\.\s*Hypothesis\s*(.+?)(?:\r?\n##)')
    $desc = ($descM.Groups[1].Value -replace '[>*`]', ' ' -replace '\s+', ' ').Trim()
    if ($desc.Length -gt 500) { $desc = $desc.Substring(0, 500) }

    [PSCustomObject]@{
        HuntId     = $huntId
        Title      = $title
        TacticSlug = $tacticSlug
        Tactics    = @(Convert-Tactic $tacticSlug | Where-Object { $_ })
        Techniques = $techniques
        Severity   = $severity
        Query      = $kql
        Description = $desc
    }
}

# Collect target cards
$cards = @()
if (Test-Path $HuntCardPath -PathType Container) {
    $cards = Get-ChildItem -Path $HuntCardPath -Filter *.md -Recurse |
             Where-Object { $_.Name -notin @('hunt-card.md') }
} else {
    $cards = @(Get-Item $HuntCardPath)
}

if (-not $cards) { throw "No Hunt Card .md files found at: $HuntCardPath" }

Write-Host "Found $($cards.Count) Hunt Card(s). Mode: $Mode" -ForegroundColor Cyan

foreach ($file in $cards) {
    $c = Read-HuntCard $file.FullName
    if (-not $c.Query) {
        Write-Warning "  [$($c.HuntId)] no KQL block found — skipping."
        continue
    }

    Write-Host "`n=== $($c.HuntId) — $($c.Title) ===" -ForegroundColor Green
    Write-Host "  Severity : $($c.Severity)"
    Write-Host "  Tactics  : $($c.Tactics -join ', ')"
    Write-Host "  Techniques: $($c.Techniques -join ', ')"

    if ($DryRun) {
        Write-Host "  [DryRun] would deploy as $Mode (query length $($c.Query.Length) chars)" -ForegroundColor Yellow
        continue
    }

    if ($Mode -eq 'ScheduledRule') {
        $template = Join-Path $scriptDir 'scheduled-query-rule.template.json'
        $params = @{
            workspaceName    = $WorkspaceName
            ruleId           = $c.HuntId
            displayName      = "$($c.HuntId) $($c.Title)"
            description      = $c.Description
            query            = $c.Query
            severity         = $c.Severity
            tactics          = $c.Tactics
            techniques       = $c.Techniques
        }
    } else {
        $template = Join-Path $scriptDir 'hunting-query.template.json'
        $params = @{
            workspaceName = $WorkspaceName
            queryId       = $c.HuntId
            displayName   = "$($c.HuntId) $($c.Title)"
            query         = $c.Query
            tactics       = $c.Tactics
            techniques    = $c.Techniques
        }
    }

    New-AzResourceGroupDeployment `
        -ResourceGroupName $ResourceGroup `
        -TemplateFile $template `
        -TemplateParameterObject $params `
        -Name ("deploy-$($c.HuntId)-" + (Get-Date -Format 'yyyyMMddHHmmss')) `
        -Verbose | Out-Null

    Write-Host "  Deployed $($c.HuntId)." -ForegroundColor Green
}

Write-Host "`nDone." -ForegroundColor Cyan
