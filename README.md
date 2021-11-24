# list-nuget-vulns

## the idea:
"dotnet list package --vulnerable --include-transitive" only shows that some package somewhere in ur project has a vulnerability.
This script is going to show you what dependencies use the vulnerable package found, so you can update that specific package, or create
an issue with the repo.

## TODO:
- [x] read dotnet command info
- [ ] parse info into obj
- [ ] check recursively for each package (using NuGet API) in .sln which one uses vulnerable ones found in step 1
