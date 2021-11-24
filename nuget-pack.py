import re
import sys
import requests
import subprocess
from package import Package
from bs4 import BeautifulSoup

# dotnet is slow asf, temp hardcoded result
result = r"""
The following sources were used:
   https://api.nuget.org/v3/index.json
   C:\Program Files (x86)\Microsoft SDKs\NuGetPackages\

Project `DAL` has the following vulnerable packages
   [net5.0]:
   Transitive Package                    Resolved   Severity   Advisory URL
   > System.Net.Http                     4.3.0      High       https://github.com/advisories/GHSA-7jgj-8wvc-jh57
   > System.Text.RegularExpressions      4.3.0      Moderate   https://github.com/advisories/GHSA-cmhx-cq75-c4mj

The given project `Domain` has no vulnerable packages given the current sources.
Project `ServiceLayer` has the following vulnerable packages
   [net5.0]:
   Transitive Package                    Resolved   Severity   Advisory URL
   > System.Net.Http                     4.3.0      High       https://github.com/advisories/GHSA-7jgj-8wvc-jh57
   > System.Text.RegularExpressions      4.3.0      Moderate   https://github.com/advisories/GHSA-cmhx-cq75-c4mj

Project `Af` has the following vulnerable packages
   [net5.0]:
   Transitive Package                    Resolved   Severity   Advisory URL
   > System.Net.Http                     4.3.0      High       https://github.com/advisories/GHSA-7jgj-8wvc-jh57
   > System.Text.RegularExpressions      4.3.0      Moderate   https://github.com/advisories/GHSA-cmhx-cq75-c4mj

Project `Tests` has the following vulnerable packages
   [net5.0]:
   Transitive Package                    Resolved   Severity   Advisory URL
   > System.Net.Http                     4.3.0      High       https://github.com/advisories/GHSA-7jgj-8wvc-jh57
   > System.Text.RegularExpressions      4.3.0      Moderate   https://github.com/advisories/GHSA-cmhx-cq75-c4mj

Project `Helpers` has the following vulnerable packages
   [net5.0]:
   Transitive Package                    Resolved   Severity   Advisory URL
   > System.Net.Http                     4.3.0      High       https://github.com/advisories/GHSA-7jgj-8wvc-jh57
   > System.Text.RegularExpressions      4.3.0      Moderate   https://github.com/advisories/GHSA-cmhx-cq75-c4mj"""

# DIR = sys.argv[1]
DIR = "..\..\inholland\StartupDesk\StartupDesk\StartupDesk.sln"
DOTNET_LIST_VULN_COMMAND = [
    "dotnet",
    "list",
    DIR,
    "package",
    "--vulnerable",
    "--include-transitive"
]

def get_transitive_vulns():
    all_vulns = []
    print(' '.join(DOTNET_LIST_VULN_COMMAND))
    # result = subprocess.run(DOTNET_LIST_VULN_COMMAND, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')
    # fuck you, this works
    found = list(set(re.findall('> .+..+..+', result)))
    for match in found:
        m = match.split()
        p = Package(m[1], m[2], m[3], m[4])
        all_vulns.append(p)

    return all_vulns

# https://azuresearch-usnc.nuget.org/query?q=System.Net.Http&prerelease=false
# https://www.nuget.org/packages/System.Net.Http/4.1.4
def get_packages_containing_vulns(vulns):
    # TODO:
    # magic.
    pass

def main():
    all_vulns = get_transitive_vulns()
    print(all_vulns)
    get_packages_containing_vulns(all_vulns)


if __name__ == "__main__":
    main()
