# WMIC Audit for MECM

A read-only Windows PowerShell tool to find WMIC references in Microsoft Configuration Manager definitions and explicitly selected source folders. Includes a standalone HTML dashboard and CSV evidence exports.

**Version: 1.4.0.** Static matches require review: they do not prove execution or deployment impact.

## Requirements

- Windows PowerShell 5.1 (`powershell.exe`), not PowerShell 7.
- Network access to the SMS Provider using WMI/DCOM.
- A user account with read access to the requested Configuration Manager objects. RBAC affects coverage.
- Read access to source folders when `SourcePaths` is used.

The ConfigurationManager PowerShell module is not required. The tool does not change site objects or execute discovered commands. It writes reports to the output directory.

## Quick start

```powershell
.\Audit-WMIC-MECM.ps1 -ProviderServer 'MECM-PROVIDER.contoso.local' -SiteCode 'P01' -OutputDirectory 'C:\Temp\WMIC-Audit'
```

To include source files:

```powershell
.\Audit-WMIC-MECM.ps1 -ProviderServer 'MECM-PROVIDER.contoso.local' -SiteCode 'P01' -SourcePaths '\\fileserver\sources','C:\Scripts' -OutputDirectory 'C:\Temp\WMIC-Audit'
```

Each run creates a unique subdirectory. Open `WMIC-Report.html` locally in a modern browser. It needs no internet connection.

## What is scanned?

| Object type | Provider class / content |
| --- | --- |
| Application | SMS_Application / SDMPackageXML |
| DeploymentType | SMS_DeploymentType / SDMPackageXML, with parent application fallback |
| PackageProgram | SMS_Program / CommandLine |
| TaskSequence | SMS_TaskSequencePackage / Sequence XML |
| ConfigurationItem | SMS_ConfigurationItem / SDMPackageXML |
| RunScript | SMS_Scripts / Script |
| SourceFile | Explicit folders: .ps1, .psm1, .psd1, .bat, .cmd, .vbs, .wsf, .js, .xml, .hta |

Latest revisions are scanned by default for classes with `IsLatest`. This does not exclude retired objects or disabled steps. External files referenced in definitions must be covered through `SourcePaths`.

## Parameters

| Parameter | Default / meaning |
| --- | --- |
| ProviderServer | Required SMS Provider hostname |
| SiteCode | Required three-character site code |
| SourcePaths | Optional array of local or UNC folders |
| OutputDirectory | `$env:TEMP\WMIC-Audit` |
| MaxFileSizeMB | 20; accepted range 1–1024 |
| IncludeHistoricalRevisions | Include historical revisions where supported; parent XML fallback is unavailable in this mode |
| SkipRunScripts | Exclude SMS_Scripts |

## Dashboard and exports

The dashboard is in English. It shows raw references, grouped findings, affected objects and errors, followed by bars by object type and WMIC usage. Search, filter by object type, and group by object type or usage. The summary always covers the full run; table filters do not change it.

The recovered definitions section is collapsed by default. **These entries are diagnostics, not WMIC findings.** A deployment type can be recovered successfully without containing WMIC.

| File | Purpose |
| --- | --- |
| WMIC-Report.html | Standalone searchable dashboard |
| WMIC-Findings.csv | Raw evidence and review classification |
| WMIC-Grouped.csv | Grouped evidence, usage category and raw reference count |
| Coverage.csv | Listed, scanned and failed counts per scope |
| Errors.csv | Failures and exclusions |
| RecoveredDefinitions.csv | Parent XML fallback diagnostics |
| Summary.json | Run metadata, scope and limitations |

CSV files use a semicolon delimiter and UTF-8 encoding. See [report interpretation](docs/REPORT.md) and [troubleshooting](docs/TROUBLESHOOTING.md).

## Limitations

This is a static text audit, not a script parser. Comments, descriptions and inactive definitions may match. Dynamically constructed WMIC commands, archives and arbitrary encoded payloads can be missed. Script-related Base64 decoding is best effort.

There is no automatic source-share, GPO or Intune discovery. Deployment status, collections, step enablement and baseline membership are not resolved. RBAC can hide objects without raising an error. `CompleteForRequestedScope` describes the requested visible scope, not the entire estate.

## Validation

Version 1.3's parent XML recovery was confirmed in a user environment. Version 1.4 preserves that recovery and changes presentation plus descriptive usage classification. Local validation covers synthetic HTML interactions and static checks; Windows PowerShell 5.1 and an SMS Provider were unavailable during development. Validate a first run against known WMIC references and inspect coverage and errors.

## Contributing and publication

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md). The sample in `examples/` is entirely synthetic. Do not publish real audit reports: they may contain internal names, paths and command-line secrets.

No open-source license has been selected. Choose and add a `LICENSE` before advertising reuse permissions. See [GitHub publication checklist](docs/PUBLISHING.md).
