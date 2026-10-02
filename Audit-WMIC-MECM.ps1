#Requires -Version 5.1
<#
.SYNOPSIS
Audits WMIC references in ConfigMgr definitions and optional source folders.
.DESCRIPTION
Read-only SMS Provider queries. No discovered script is executed.
Requires Windows PowerShell 5.1 and read access to the SMS Provider (DCOM).
XML locations identify fields; line numbers refer to the field/script, not the UI.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ProviderServer,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9]{3}$')][string]$SiteCode,
    [string[]]$SourcePaths = @(),
    [string]$OutputDirectory = (Join-Path $env:TEMP 'WMIC-Audit'),
    [ValidateRange(1,1024)][int]$MaxFileSizeMB = 20,
    [switch]$IncludeHistoricalRevisions,
    [switch]$SkipRunScripts
)
$ErrorActionPreference = 'Stop'
$namespace = 'root\SMS\site_' + $SiteCode
$findings = New-Object 'System.Collections.Generic.List[object]'
$coverage = New-Object 'System.Collections.Generic.List[object]'
$issues = New-Object 'System.Collections.Generic.List[object]'
$pattern = '(?i)(?<![\w-])wmic(?:\.exe)?(?![\w-])'
$recoveries = New-Object 'System.Collections.Generic.List[object]'
$parentXmlCache = @{}
$extensions = @('.ps1','.psm1','.psd1','.bat','.cmd','.vbs','.wsf','.js','.xml','.hta')

function Add-Issue([string]$Scope,[string]$ObjectId,[string]$Message) {
    $issues.Add([pscustomobject]@{ Scope=$Scope; ObjectId=$ObjectId; Message=$Message })
}
function Get-WmicUsageType([string]$Text) {
    # Descriptive text classification, never proof of execution.
    if ($Text -match '(?i)TriggerSchedule') { return 'Client schedule trigger' }
    if ($Text -match '(?i)\bprocess\b.*\b(call\s+create|create)\b') { return 'Process creation' }
    if ($Text -match '(?i)\b(call|delete|set)\b') { return 'Method or change operation' }
    if ($Text -match '(?i)\b(get|list)\b') { return 'Inventory or query' }
    return 'Other WMIC reference'
}
function Find-Reference {
    param([string]$Text,[string]$Type,[string]$Name,[string]$Id,[string]$Location,
          [string]$Representation='PlainText')
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    $lines = [regex]::Split($Text, '\r\n|\n|\r')
    for ($i=0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match $pattern) {
            $candidate = 'ReferenceToReview'
            if ($lines[$i].TrimStart() -match '^(#|REM\s|::|//|<!--)') {
                $candidate = 'PossibleComment'
            }
            $findings.Add([pscustomobject]@{
                ObjectType=$Type; ObjectName=$Name; ObjectId=$Id
                Location=$Location; LineNumber=($i+1)
                Classification=$candidate; Representation=$Representation
                Evidence=$lines[$i].Trim()
            })
        }
    }
}
function Search-Value {
    param([string]$Text,[string]$Type,[string]$Name,[string]$Id,[string]$Location,
          [switch]$TryBase64)
    Find-Reference $Text $Type $Name $Id $Location
    # Only try Base64 for script-related fields. Never execute the result.
    if ($TryBase64 -and $Text -notmatch $pattern) {
        $compact = $Text -replace '\s',''
        if ($compact.Length -ge 8 -and ($compact.Length % 4) -eq 0 -and
            $compact -match '^[A-Za-z0-9+/]+={0,2}$') {
            try {
                $bytes = [Convert]::FromBase64String($compact)
                $decoded = [Text.Encoding]::UTF8.GetString($bytes)
                if ($decoded.Contains([char]0)) {
                    $decoded = [Text.Encoding]::Unicode.GetString($bytes)
                }
                Find-Reference $decoded $Type $Name $Id $Location 'DecodedBase64'
            } catch { }
        }
    }
}
function Get-DeploymentTypeFallback($Item) {
    $parentName = [string]$Item.Properties['AppModelName'].Value
    $model = [string]$Item.Properties['ModelName'].Value
    if (-not $model) { $model = [string]$Item.Properties['CI_UniqueID'].Value }
    $match = [regex]::Match($model, 'DeploymentType_[^/]+')
    if (-not $parentName -or -not $match.Success) { throw 'Parent application or deployment type identity unavailable.' }
    if (-not $parentXmlCache.ContainsKey($parentName)) {
        $escaped = $parentName.Replace('\','\\').Replace("'","\'")
        $parents = @(Get-WmiObject -ComputerName $ProviderServer -Namespace $namespace -Class SMS_Application -Filter "ModelName = '$escaped'" -Property CI_ID,ModelName,IsLatest -ErrorAction Stop)
        $parentText = $null
        try {
            $latest = @($parents | Where-Object { $_.IsLatest })
            if ($latest.Count -ne 1) { throw 'Exactly one current parent application could not be identified.' }
            $latest[0].Get()
            $parentText = [string]$latest[0].Properties['SDMPackageXML'].Value
            if ([string]::IsNullOrWhiteSpace($parentText)) { throw 'Parent application XML is empty.' }
            $parentXmlCache[$parentName] = $parentText
        } finally { foreach ($parent in $parents) { $parent.Dispose() } }
    }
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    # Reject DTD before parsing this provider-owned definition.
    $xml = [string]$parentXmlCache[$parentName]
    if ($xml -match '<!DOCTYPE') { throw 'DTD is not allowed.' }
    $doc.LoadXml($xml)
    $scope = ($model -split '/')[0]
    $uniqueId = [string]$Item.Properties['CI_UniqueID'].Value
    $revisionMatch = [regex]::Match($uniqueId, '/(\d+)$')
    $nodes = @($doc.SelectNodes("//*[local-name()='DeploymentType']") | Where-Object {
        $_.GetAttribute('LogicalName') -eq $match.Value -and
        $_.GetAttribute('AuthoringScopeId') -eq $scope -and
        ($_.SelectNodes("./*[local-name()='Installer']").Count -gt 0) -and
        (-not $revisionMatch.Success -or $_.GetAttribute('Version') -eq $revisionMatch.Groups[1].Value)
    })
    if ($nodes.Count -ne 1) { throw 'Deployment type Installer definition was not uniquely matched by scope, logical name and version in current parent XML.' }
    return $nodes[0].OuterXml
}

function Get-NodeLocation([System.Xml.XmlNode]$Node) {
    $parts = New-Object 'System.Collections.Generic.List[string]'
    $current = $Node
    while ($null -ne $current -and $current.NodeType -eq 'Element') {
        $part = $current.LocalName
        foreach ($key in @('name','Name','id','ID','LogicalName')) {
            $attr = $current.Attributes.GetNamedItem($key)
            if ($null -ne $attr) { $part += "[$key=$($attr.Value)]"; break }
        }
        # Include sibling position to distinguish identically named steps.
        $position=1
        $previous=$current.PreviousSibling
        while ($null -ne $previous) {
            if ($previous.NodeType -eq 'Element' -and $previous.LocalName -eq $current.LocalName) { $position++ }
            $previous=$previous.PreviousSibling
        }
        $part += "[position=$position]"
        $parts.Insert(0,$part)
        $current = $current.ParentNode
    }
    return '/' + ($parts -join '/')
}
function Search-Xml {
    param([string]$Text,[string]$Type,[string]$Name,[string]$Id,[string]$Field)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        throw "Empty $Field definition; coverage cannot be confirmed."
    }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $inputReader = New-Object System.IO.StringReader($Text)
    $reader = $null
    try {
        $reader = [System.Xml.XmlReader]::Create($inputReader,$settings)
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($reader)
        foreach ($node in $doc.SelectNodes('//*')) {
            $location = $Field + (Get-NodeLocation $node)
            foreach ($attribute in $node.Attributes) {
                Search-Value $attribute.Value $Type $Name $Id ($location + '/@' + $attribute.Name)
            }
            # Scan direct text nodes only; avoid reporting ancestor copies.
            foreach ($child in $node.ChildNodes) {
                if ($child.NodeType -in @('Text','CDATA')) {
                    $scriptField = ($node.LocalName -match 'Script|Body') -or
                        ($node.OuterXml -match 'name="(?:Script|ScriptBody|ScriptText)"')
                    Search-Value $child.Value $Type $Name $Id $location -TryBase64:$scriptField
                }
            }
        }
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        $inputReader.Dispose()
    }
}

if ($PSVersionTable.PSEdition -eq 'Core') {
    throw 'Use Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.'
}
if ($null -eq (Get-Command Get-WmiObject -ErrorAction SilentlyContinue)) {
    throw 'Get-WmiObject is required on Windows PowerShell 5.1.'
}
$runDirectory = Join-Path $OutputDirectory ((Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + [guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $runDirectory -Force
$revisionFilter = 'IsLatest = 1'
if ($IncludeHistoricalRevisions) { $revisionFilter = '' }
$specs = @(
    @{Class='SMS_Application'; Type='Application'; Name='LocalizedDisplayName'; Id='CI_ID'; Fields=@('SDMPackageXML'); Xml=$true; Filter=$revisionFilter},
    @{Class='SMS_DeploymentType'; Type='DeploymentType'; Name='LocalizedDisplayName'; Id='CI_ID'; Fields=@('SDMPackageXML'); Xml=$true; Filter=$revisionFilter},
    @{Class='SMS_Program'; Type='PackageProgram'; Name='ProgramName'; Id='PackageID'; Fields=@('CommandLine'); Xml=$false; Filter=''},
    @{Class='SMS_TaskSequencePackage'; Type='TaskSequence'; Name='Name'; Id='PackageID'; Fields=@('Sequence'); Xml=$true; Filter=''},
    @{Class='SMS_ConfigurationItem'; Type='ConfigurationItem'; Name='LocalizedDisplayName'; Id='CI_ID'; Fields=@('SDMPackageXML'); Xml=$true; Filter=$revisionFilter}
)
if (-not $SkipRunScripts) {
    $specs += @{Class='SMS_Scripts'; Type='RunScript'; Name='ScriptName'; Id='ScriptGuid'; Fields=@('Script'); Xml=$false; Filter=''}
}

foreach ($spec in $specs) {
    Write-Host "Reading $($spec.Class)..."
    $listed = 0; $scanned = 0; $failed = 0; $status = 'Complete'
    try {
        $queryArgs = @{ ComputerName=$ProviderServer; Namespace=$namespace; Class=$spec.Class; ErrorAction='Stop' }
        # Enumerate identifiers only, then read each definition individually.
        # Avoid a SELECT * on classes containing large/lazy CI definitions.
        $queryArgs.Property = @($spec.Id, $spec.Name)
        if ($spec.Filter) {
            $queryArgs.Property += 'IsLatest'
            $queryArgs.Filter = $spec.Filter
        }
        $clientRevisionFilter = $false
        try {
            $objects = @(Get-WmiObject @queryArgs)
        } catch {
            $firstError = $_.Exception.Message
            if (-not $spec.Filter) { throw }
            Write-Warning "$($spec.Class): filtered query failed ($firstError). Retrying identifier enumeration without the filter."
            $queryArgs.Remove('Filter')
            $clientRevisionFilter = $true
            $objects = @(Get-WmiObject @queryArgs)
        }
        foreach ($item in $objects) {
            if ($clientRevisionFilter) {
                $latestProperty = $item.Properties['IsLatest']
                if ($null -eq $latestProperty -or $null -eq $latestProperty.Value) {
                    $item.Get()
                    $latestProperty = $item.Properties['IsLatest']
                }
                if ($null -eq $latestProperty -or $null -eq $latestProperty.Value) {
                    $item.Dispose()
                    throw 'IsLatest unavailable during fallback; revision scope cannot be confirmed.'
                }
                if (-not [bool]$latestProperty.Value) { $item.Dispose(); continue }
            }
            $listed++
            $id = [string]$item.Properties[$spec.Id].Value
            try {
                # Explicit Get hydrates lazy properties; it does not write to WMI.
                $item.Get()
                $name = [string]$item.Properties[$spec.Name].Value
                if ($spec.Type -eq 'PackageProgram') { $id += '/' + $name }
                foreach ($field in $spec.Fields) {
                    $property = $item.Properties[$field]
                    if ($null -eq $property) { throw "Property $field is unavailable." }
                    $value = $property.Value
                    if ($value -is [byte[]]) {
                        $text = [Text.Encoding]::UTF8.GetString($value)
                        if ($text.Contains([char]0)) { $text = [Text.Encoding]::Unicode.GetString($value) }
                    } else { $text = [string]$value }
                    if ($spec.Type -eq 'DeploymentType' -and [string]::IsNullOrWhiteSpace($text)) {
                        try {
                            if ($IncludeHistoricalRevisions) { throw 'Parent fallback is restricted to current revision audits.' }
                            $text = Get-DeploymentTypeFallback $item
                            $recoveries.Add([pscustomobject]@{ObjectId=$id;ObjectName=$name;Method='MatchedDeploymentTypeInCurrentParentXML'})
                        } catch { throw ('Empty deployment type XML; fallback failed: ' + $_.Exception.Message) }
                    }
                    if ($spec.Xml) {
                        Search-Xml $text $spec.Type $name $id $field
                    } else {
                        if ($spec.Type -eq 'RunScript' -and [string]::IsNullOrWhiteSpace($text)) {
                            throw 'Script body is empty or unavailable.'
                        }
                        Search-Value $text $spec.Type $name $id $field -TryBase64:($spec.Type -eq 'RunScript')
                    }
                }
                $scanned++
            } catch {
                $failed++
                Add-Issue $spec.Class $id $_.Exception.Message
            } finally { $item.Dispose() }
        }
        if ($failed -gt 0) { $status='Partial' }
    } catch {
        $status='FailedOrPartial'
        $detail = $_.Exception.ToString()
        if ($_.Exception -is [System.Management.ManagementException]) {
            $detail += ' | WMI ErrorCode=' + $_.Exception.ErrorCode
            if ($null -ne $_.Exception.ErrorInformation) {
                $detail += ' | Provider=' + $_.Exception.ErrorInformation.GetText([System.Management.TextFormat]::Mof)
            }
        }
        $detail += ' | Namespace=' + $namespace + ' | Properties=' + ($queryArgs.Property -join ',')
        if ($queryArgs.ContainsKey('Filter')) { $detail += ' | Filter=' + $queryArgs.Filter }
        Add-Issue $spec.Class '' $detail
    }
    $coverage.Add([pscustomobject]@{Scope=$spec.Class; Listed=$listed; Scanned=$scanned; Failed=$failed; Status=$status})
}

$seenFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($source in $SourcePaths) {
    Write-Host "Scanning folder $source..."
    $listed=0; $scanned=0; $failed=0; $status='Complete'; $enumerationErrors=@()
    try {
        if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'Folder is inaccessible or does not exist.' }
        Get-ChildItem -LiteralPath $source -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable enumerationErrors |
            Where-Object { $_.Extension.ToLowerInvariant() -in $extensions } |
            ForEach-Object {
                $file=$_
                if ($seenFiles.Add($file.FullName)) {
                    $listed++
                    try {
                        if ($file.Length -gt ($MaxFileSizeMB * 1MB)) { throw 'File exceeds MaxFileSizeMB; skipped.' }
                        # StreamReader detects BOM, otherwise uses UTF-8. Plain WMIC is ASCII.
                        $stream = New-Object System.IO.StreamReader($file.FullName)
                        try { $text=$stream.ReadToEnd() } finally { $stream.Dispose() }
                        Find-Reference $text 'SourceFile' $file.Name $file.FullName $file.FullName
                        $scanned++
                    } catch { $failed++; Add-Issue 'SourceFile' $file.FullName $_.Exception.Message }
                }
            }
        foreach ($entry in $enumerationErrors) { Add-Issue 'FolderEnumeration' $source $entry.ToString() }
        if ($failed -gt 0 -or $enumerationErrors.Count -gt 0) { $status='Partial' }
    } catch { $status='FailedOrPartial'; Add-Issue 'SourceFolder' $source $_.Exception.Message }
    $coverage.Add([pscustomobject]@{Scope=$source; Listed=$listed; Scanned=$scanned; Failed=$failed; Status=$status})
}

function Export-Report($Rows,[string]$Path,[string]$Header) {
    if ($Rows.Count -gt 0) { $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Delimiter ';' }
    else { Set-Content -LiteralPath $Path -Value $Header -Encoding UTF8 }
}
$unique = @($findings | Sort-Object ObjectType,ObjectId,Location,LineNumber,Representation,Evidence -Unique)
Export-Report $unique (Join-Path $runDirectory 'WMIC-Findings.csv') 'ObjectType;ObjectName;ObjectId;Location;LineNumber;Classification;Representation;Evidence'
Export-Report $coverage (Join-Path $runDirectory 'Coverage.csv') 'Scope;Listed;Scanned;Failed;Status'
Export-Report $issues (Join-Path $runDirectory 'Errors.csv') 'Scope;ObjectId;Message'
# Preserve all raw evidence, additionally merge identical commands within a TS step.
$groups = @{}
foreach ($row in $unique) {
    $location=$row.Location
    $command=$row.Evidence
    if ($row.ObjectType -eq 'TaskSequence') {
        $m=[regex]::Match($location,'^.*?/step\[.*?\]\[position=\d+\]')
        if ($m.Success) { $location=$m.Value }
        $command=$command -replace '^smsswd\.exe\s+/run:\s*',''
    }
    $key=(@($row.ObjectType,$row.ObjectId,$location,$row.LineNumber,$command) | ConvertTo-Json -Compress)
    if (-not $groups.ContainsKey($key)) {
        $groups[$key]=[pscustomobject]@{ObjectType=$row.ObjectType;ObjectName=$row.ObjectName;ObjectId=$row.ObjectId;Location=$location;LineNumber=$row.LineNumber;UsageType=(Get-WmicUsageType $command);Evidence=$command;RawReferences=0}
    }
    $groups[$key].RawReferences++
}
$grouped=@($groups.Values | Sort-Object ObjectType,ObjectId,Location,LineNumber)
Export-Report $grouped (Join-Path $runDirectory 'WMIC-Grouped.csv') 'ObjectType;ObjectName;ObjectId;Location;LineNumber;UsageType;Evidence;RawReferences'
Export-Report $recoveries (Join-Path $runDirectory 'RecoveredDefinitions.csv') 'ObjectId;ObjectName;Method'
$summary = [pscustomobject]@{
    Version='1.4.0'; Timestamp=(Get-Date).ToString('o'); ProviderServer=$ProviderServer; SiteCode=$SiteCode
    Findings=$unique.Count; GroupedFindings=$grouped.Count; RecoveredDefinitions=$recoveries.Count; Issues=$issues.Count
    Status=$(if ($issues.Count -gt 0) {'Partial'} else {'CompleteForRequestedScope'})
    RevisionScope=$(if ($IncludeHistoricalRevisions) {'All'} else {'Latest'})
    RunScriptsIncluded=(-not $SkipRunScripts.IsPresent); SourcePaths=$SourcePaths
    Limitations=@('Visible objects only: RBAC applies.','Static text search, not proof of execution.',
        'No automatic discovery of source shares, GPOs or Intune.',
        'No archive extraction; dynamically constructed commands or arbitrary encoded payloads may be missed.',
        'Embedded Base64 decoding is best effort; comments and descriptions may match.',
        'Baseline membership, deployment status and impact are not resolved.',
        'Recovered deployment definitions use a uniquely matched node in current parent application XML.')
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runDirectory 'Summary.json') -Encoding UTF8
function ConvertTo-SafeHtmlTable($Rows, [string[]]$Columns) {
    $builder=New-Object Text.StringBuilder
    $null=$builder.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($column in $Columns) { $null=$builder.Append('<th>'+[System.Net.WebUtility]::HtmlEncode($column)+'</th>') }
    $null=$builder.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        $null=$builder.Append('<tr>')
        foreach ($column in $Columns) {
            $value=[string]$row.$column
            $null=$builder.Append('<td>'+[System.Net.WebUtility]::HtmlEncode($value)+'</td>')
        }
        $null=$builder.Append('</tr>')
    }
    $null=$builder.Append('</tbody></table></div>')
    return $builder.ToString()
}
$coverageHtml=ConvertTo-SafeHtmlTable $coverage @('Scope','Listed','Scanned','Failed','Status')
$findingsHtml=ConvertTo-SafeHtmlTable $grouped @('ObjectType','ObjectName','ObjectId','UsageType','Location','LineNumber','Evidence','RawReferences')
$errorsHtml=ConvertTo-SafeHtmlTable $issues @('Scope','ObjectId','Message')
$recoveriesHtml=ConvertTo-SafeHtmlTable $recoveries @('ObjectId','ObjectName','Method')
$affectedCount=@($unique | Select-Object ObjectType,ObjectId -Unique).Count
$providerHtml=[Net.WebUtility]::HtmlEncode($ProviderServer)
$stateHtml=[Net.WebUtility]::HtmlEncode($summary.Status)
$html=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WMIC audit · MECM</title>
<style>
body{margin:0;background:#f1f5fa;color:#142c49;font:15px system-ui,sans-serif}main{max-width:1500px;margin:auto;padding:32px}header{border-left:6px solid #f6554b;padding:8px 24px;margin-bottom:24px}h1{font-size:34px;margin:0}h2{margin-top:0}.cards,.charts,.controls{display:flex;flex-wrap:wrap;gap:14px}.card,section{background:white;border:1px solid #dde4ef;border-radius:12px;padding:22px;margin-bottom:20px}.card{flex:1;min-width:150px}.card strong{display:block;font-size:30px}.note{background:#fff3de;padding:16px;border-radius:8px}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:10px;border-bottom:1px solid #e5eaf1;vertical-align:top}th{background:#edf3fa}td{overflow-wrap:anywhere;max-width:550px;white-space:pre-wrap}input,select{padding:10px;border:1px solid #bbc8d9;border-radius:6px;max-width:100%;box-sizing:border-box}input{width:360px}.controls label{display:grid;gap:6px}.controls{margin-bottom:18px}footer,.muted{color:#60738b;font-size:13px}.charts>div{flex:1;min-width:260px}.bar-item{margin:15px 0}.bar-label{display:flex;justify-content:space-between;gap:15px;font-size:14px}.track{background:#edf3fa;height:10px;border-radius:6px;margin-top:6px;overflow:hidden}.fill{height:100%;background:#f6554b}.charts>div:nth-child(2) .fill{background:#23496f}summary{cursor:pointer;font-weight:600;font-size:19px}details[open] summary{margin-bottom:15px}.group-heading th{background:#dce7f4;font-size:14px}tr[hidden]{display:none!important}.empty{padding:15px;color:#60738b}@media(max-width:600px){main{padding:16px}h1{font-size:26px}.card{min-width:110px}}@media print{body{background:white}main{padding:0}.table-wrap{overflow:visible}.controls{display:none}.card,section{border-radius:0}}
</style></head><body><main><header><h1>WMIC audit · MECM</h1><p>Lijane Consulting · $providerHtml · Site $SiteCode · $($summary.Timestamp)</p><b>Coverage: $stateHtml</b></header>
<div class="cards"><div class="card"><strong>$($unique.Count)</strong>Raw references</div><div class="card"><strong>$($grouped.Count)</strong>Grouped findings</div><div class="card"><strong>$affectedCount</strong>Affected objects</div><div class="card"><strong>$($issues.Count)</strong>Errors / exclusions</div></div>
<p class="note">Static analysis of visible objects and requested folders. A reference is not proof of execution. Deployments and step enablement are not checked. Any failure leaves part of the requested coverage unconfirmed.</p>
<section><h2>Findings overview</h2><p class="muted">Counts use grouped findings. Objects may appear in more than one usage category. Filters below affect the findings table only.</p><div class="charts"><div><h3>By object type</h3><div id="objectChart"></div></div><div><h3>By WMIC usage</h3><div id="usageChart"></div></div></div></section>
<section><h2>Audit coverage</h2>$coverageHtml</section>
<section id="findings"><h2>References to review</h2><div class="controls"><label>Search<input id="search" type="search" placeholder="Object, step or command"></label><label>Object type<select id="typeFilter"><option value="">All types</option></select></label><label>Group by<select id="groupBy"><option value="none">No grouping</option><option value="object" selected>Object type</option><option value="usage">WMIC usage</option></select></label></div><p id="resultCount" class="muted" aria-live="polite"></p>$findingsHtml<p id="noResults" class="empty" hidden>No matching findings.</p></section>
<section><details><summary>Definitions recovered from parent applications · $($recoveries.Count)</summary><p class="muted">Diagnostic information only. These objects required a fallback to their parent application XML. Being listed here does not mean they contain WMIC.</p>$recoveriesHtml</details></section>
<section><h2>Errors and exclusions · $($issues.Count)</h2>$errorsHtml</section>
<footer>Standalone report with no external resources. Raw and grouped CSV files are available in the same folder. Source files are scanned only when SourcePaths is specified. Report version 1.4.0.</footer></main>
<script>
(function(){
'use strict';
const tbody=document.querySelector('#findings tbody');
const rows=Array.from(tbody.rows);
const search=document.getElementById('search'), filter=document.getElementById('typeFilter'), grouping=document.getElementById('groupBy');
const records=rows.map(row=>({row,type:row.cells[0].textContent,name:row.cells[1].textContent,id:row.cells[2].textContent,usage:row.cells[3].textContent,text:row.textContent.toLowerCase()}));
function uniqueObjects(items){return new Set(items.map(r=>JSON.stringify([r.type,r.id]))).size;}
function buckets(items,key){const result=new Map();items.forEach(r=>{const label=r[key];if(!result.has(label))result.set(label,[]);result.get(label).push(r);});return Array.from(result).sort((a,b)=>b[1].length-a[1].length||a[0].localeCompare(b[0]));}
function chart(target,key){const el=document.getElementById(target), groups=buckets(records,key), max=Math.max(1,...groups.map(g=>g[1].length));if(!groups.length){el.textContent='No findings.';return;}groups.forEach(([label,items])=>{const box=document.createElement('div');box.className='bar-item';const line=document.createElement('div');line.className='bar-label';const title=document.createElement('span');title.textContent=label;const count=document.createElement('span');count.textContent=items.length+' findings · '+uniqueObjects(items)+' objects';line.append(title,count);const track=document.createElement('div');track.className='track';const fill=document.createElement('div');fill.className='fill';fill.style.width=(100*items.length/max)+'%';track.append(fill);box.append(line,track);el.append(box);});}
Array.from(new Set(records.map(r=>r.type))).sort().forEach(type=>{const option=document.createElement('option');option.value=type;option.textContent=type;filter.append(option);});
function render(){tbody.querySelectorAll('.group-heading').forEach(r=>r.remove());const q=search.value.toLowerCase();const visible=records.filter(r=>(!filter.value||r.type===filter.value)&&r.text.includes(q));records.forEach(r=>{r.row.hidden=true;tbody.append(r.row);});const key=grouping.value==='object'?'type':'usage';if(grouping.value==='none'){visible.forEach(r=>{r.row.hidden=false;tbody.append(r.row);});}else{buckets(visible,key).forEach(([label,items])=>{const heading=document.createElement('tr');heading.className='group-heading';const cell=document.createElement('th');cell.colSpan=8;cell.textContent=label+' · '+items.length+' findings · '+uniqueObjects(items)+' objects';heading.append(cell);tbody.append(heading);items.forEach(r=>{r.row.hidden=false;tbody.append(r.row);});});}document.getElementById('resultCount').textContent=visible.length+' of '+records.length+' grouped findings · '+uniqueObjects(visible)+' affected objects';document.getElementById('noResults').hidden=visible.length!==0;}
chart('objectChart','type');chart('usageChart','usage');search.addEventListener('input',render);filter.addEventListener('change',render);grouping.addEventListener('change',render);render();
})();
</script></body></html>
"@
Set-Content -LiteralPath (Join-Path $runDirectory 'WMIC-Report.html') -Value $html -Encoding UTF8
$coverage | Format-Table -AutoSize
Write-Host "References: $($unique.Count); grouped: $($grouped.Count); recovered: $($recoveries.Count); issues: $($issues.Count). Reports: $runDirectory"
if ($issues.Count -gt 0) { Write-Warning 'Audit is incomplete. Check coverage and errors in WMIC-Report.html.' }
