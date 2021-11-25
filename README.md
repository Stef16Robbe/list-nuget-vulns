# list-nuget-vulns

## the idea:
`dotnet list package --vulnerable --include-transitive` only shows that some package somewhere in ur project has a vulnerability.
This script is going to show you what dependencies use the vulnerable package found, so you can update that specific package, or create
an issue with the repo.

## TODO:
- [x] read dotnet command info
- [x] parse info into obj
- [x] get all packages in solution
- [ ] get all dependencies from each package
- [ ] check in what 'tree' the vuln exists
- [ ] show results in tree thingy(?)
