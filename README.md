RegLister
=============

Recurse through a registry, identifying values with large data
Written by David Longenecker (Twitter: @dnlongen)

Registry values with large amounts of data are one way of hiding malicious executable data. The registry is persistent so the malware can remain through a reboot, but the malware is not on disk so is not detected by traditional AV.

See http://www.codereversing.com/blog/archives/261 for an explanation of how this works.

Rev 0.1 recursively dives through the registry on an online Windows system, scanning each of the five hives for any data greater than 20kb by default. You can adjust this by changing the "minsize" value in the source code.

Requirements:
=============

* Currently written for Python 3
* As it reads the registry from the current system, it naturally only works on windows :-)
* requires winreg, argparse, sys

Usage:
=============

```
reglister.py [-h] [--minsize MINSIZE] [-v]

Recursively scan a Windows registry and print the values with the largest
data.

optional arguments:
  -h, --help         show this help message and exit
  --minsize MINSIZE  Show all data larger than this; default 20KB
  -v, --verbose      Display verbose error messages; this will show errors for
                     registry values to which you do not have access
```

Other Options:
=============

*whitelist* is a dictionary of legitimate registry values known to contain large data entries; anything in this whitelist will be ignored by RegLister. The default whitelist follows but can be adjusted to suit your needs.

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
3. Add support for a remote Windows registry
