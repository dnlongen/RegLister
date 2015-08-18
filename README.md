RegLister
=============

Recurse through a registry, identifying values with large data

* Written by David Longenecker
* Twitter: @dnlongen
* Email: david (at) securityforrealpeople.com
* More info: http://www.securityforrealpeople.com/reglister

Registry values with large amounts of data are one way of hiding malicious executable data. The registry is persistent so the malware can remain through a reboot, but the malware is not on disk so is not detected by traditional AV.

See http://www.codereversing.com/blog/archives/261 for an explanation of how this works.

Rev 0.2 recursively dives through the registry on an online Windows system, scanning each of the five hives for any data greater than 20kb by default. You can adjust this by supplying a "--minsize" parameter (in KB) on the command line. It also supports remote registries via the "--computername" parameter.

Note that for remote registry access, the remote PC must have the *Remote Registry* service enabled and running, and must either have its Windows Firewall disabled or set to allow incoming remote registry connections. RegLister does not currently authenticate to the remote registry, thus you must map a drive or a null session with an account with admin rights on the remote PC first.

Requirements:
=============

* Currently written for **Python 3**
* As it reads the registry from the current system, it naturally only works on Windows :-)
* requires winreg, argparse, sys

Usage:
=============

```
reglister.py [-h] [-c COMPUTERNAME] [-m MINSIZE] [-v] [-d]

Recursively scan a Windows registry and print keys and values with a large
data content. Hiding executable files in the registry is a common malware
technique; as such files tend to be larger than most normal registry data,
RegLister helps locate potentially suspicious registry data.

optional arguments:
  -h, --help            show this help message and exit
  -c COMPUTERNAME, --computername COMPUTERNAME
                        Remote computername to connect; if not specified, the
                        local registry will be used
  -m MINSIZE, --minsize MINSIZE
                        Show all data larger than this; default 20KB
  -v, --verbose         Display verbose error messages; this will show errors
                        for registry values to which you do not have access
  -d, --debug
```

Other Options:
=============

*whitelist* is a dictionary of legitimate registry values known to contain large data entries; anything in this whitelist will be ignored by RegLister. The default whitelist follows but can be adjusted in the source code to suit your needs.

```
whitelist = [
  "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications\AppDB",
  "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\IconStreams",
  "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\PastIconsStream",
  "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\IconStreams",
  "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\PastIconsStream"
]
```

Planned enhancements:
=============

1. Add support for analyzing offline registries
2. Add a "top n" function to report only the "n" largest data values
