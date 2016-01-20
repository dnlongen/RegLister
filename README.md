RegLister
=============

Recurse through a registry, identifying values with large data

* Written by David Longenecker
* Twitter: @dnlongen
* Email: david (at) securityforrealpeople.com
* More info: http://www.securityforrealpeople.com/reglister

Registry values with large amounts of data are one way of hiding malicious executable data. The registry is persistent so the malware can remain through a reboot, but the malware is not on disk so is not detected by traditional AV.

RegLister recursively dives through the registry on a Windows system. For a live system, RegLister will scanning each of the five hives; if a registry filename is specified, RegLister will scan that specific offline file. By default RegLister will show any data greater than 20kb. You can adjust this by supplying a "--minsize" parameter (in KB) on the command line.

RegLister supports remote registries via the "--computername" parameter. It supports offline file analysis via the "--filename" parameter. Naturally these two parameters are mutually exclusive. If neither value is specified, it will scan the local live system.

Note that for remote registry access, the remote PC must have the *Remote Registry* service enabled and running, and must either have its Windows Firewall disabled or set to allow incoming remote registry connections. RegLister does not currently authenticate to the remote registry, thus you must map a drive or a null session with an account with admin rights on the remote PC first.

Hat tip to Patrick Olsen (@patrickrolsen) for example code that helped with parsing offline files.

Requirements:
=============

* Currently written for **Python 3**
* requires argparse, sys
* Live analysis requires winreg; as it reads the registry from the current system, it naturally only works on Windows :-) If this module is not present, RegLister will still function, but without live analysis available.
* For offline file analysis, requires the python-registry module by @willibalenthin, available from https://github.com/williballenthin/python-registry. If this module is not installed, RegLister will still function, but without offline analysis available.
* Tested with Python 3.4.3 and python-registry 1.1.0. Use other versions at your own risk. **RegLister will not run in Python 2.x**

Usage:
=============

```
reglister.py [-h] [-c COMPUTERNAME | -f FILENAME] [-m MINSIZE] [-v] [-d]

Recursively scan a Windows registry and print keys and values with a large
data content. Hiding executable files in the registry is a common malware
technique; as such files tend to be larger than most normal registry data,
RegLister helps locate potentially suspicious registry data.

optional arguments:
  -h, --help            show this help message and exit
  -c COMPUTERNAME, --computername COMPUTERNAME
                        Remote computername to connect; if not specified, the
                        local registry will be used
  -f FILENAME, --filename FILENAME
                        Specify a registry hive filename to load for offline
                        analysis. Note: --computername and --filename are
                        mutually exclusive
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

1. Add a "top n" function to report only the "n" largest data values
2. Add an option to write large data to disk for further analysis

Change Log:
=============

* v0.4 Added support for Linux, fixed an error in computing data length
* v0.3 Added support for offline registry files
* v0.2 Added support for remote registries
* v0.1 Original release. Local, offline analysis only.

Errata:
=============

* The python_registry module throws a TypeError attempting to read the value of certain registry keys, in particular many of type RegMultiSZ. At present, RegLister misses some large data values because it errors attempting to read the values.
