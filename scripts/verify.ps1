$ErrorActionPreference = 'Stop'
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'The .NET 10 SDK is required; no build or tests were run.'
}
function Invoke-Dotnet {
    & dotnet @args
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed with exit code $LASTEXITCODE" }
}
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $env:TESTINGPLATFORM_TELEMETRY_OPTOUT = '1'
    $project = 'tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj'
    Invoke-Dotnet --info
    Invoke-Dotnet restore $project
    Invoke-Dotnet build $project --configuration Release --no-restore
    Invoke-Dotnet run --project $project --configuration Release --no-build
}
finally { Pop-Location }
