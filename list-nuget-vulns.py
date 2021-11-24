import os
import re
import sys
import requests
import subprocess
from vulnerability import Vulnerability
from bs4 import BeautifulSoup
from typing import List

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
DIR = ""
NUGET_PKG_INFO_URL = "https://azuresearch-usnc.nuget.org/query?q="

def get_transitive_vulns():
    all_vulns = []
    # command = [
    #     "dotnet",
    #     "list",
    #     DIR,
    #     "package",
    #     "--vulnerable",
    #     "--include-transitive"
    # ]
    # result = subprocess.run(command, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')
    # # fuck you, this works
    found = list(set(re.findall('> .+..+..+', result)))
    for match in found:
        m = match.split()
        v = Vulnerability(m[1], m[2], m[3], m[4])
        all_vulns.append(v)

    return all_vulns

def get_solution_packages(solution):
    all_pkgs = []
    command = [
        "dotnet",
        "list",
        solution,
        "package"
    ]
    
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')
    found = list(set(re.findall('> .+..+..+', result)))
    for match in found:
        m = match.split()
        v = (m[1], m[3])
        all_pkgs.append(v)
    
    return all_pkgs

def main():
    try:
        DIR = sys.argv[1]
    except Exception:
        print("missing dir variable, assuming current dir is a solution")
        DIR = ""

    solution = ""
    for root, _, files in os.walk(DIR):
        for file in files:
            if file.endswith('.sln'):
                solution = root+'/'+str(file)

    if solution == "":
        print("no solution found in given folder")
        quit()

    all_vulns: List[Vulnerability] = get_transitive_vulns()
    print(str(all_vulns) + "\n")

    all_pkgs = get_solution_packages(solution)
    print(all_pkgs)
    # https://www.nuget.org/packages/System.Net.Http/4.1.4


if __name__ == "__main__":
    main()
