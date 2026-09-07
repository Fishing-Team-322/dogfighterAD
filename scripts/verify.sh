#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v dotnet >/dev/null 2>&1; then
  echo "The .NET 10 SDK is required; no build or tests were run." >&2
  exit 127
fi
export TESTINGPLATFORM_TELEMETRY_OPTOUT=1
project=tests/DogfighterAD.Core.Tests/DogfighterAD.Core.Tests.csproj
dotnet --info
dotnet restore "$project"
dotnet build "$project" --configuration Release --no-restore
# This repository uses the xUnit v3 executable/Microsoft Testing Platform runner.
dotnet run --project "$project" --configuration Release --no-build
