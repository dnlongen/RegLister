# RegLister
Recurse through a registry, identifying values with large data
Written by David Longenecker (Twitter: @dnlongen)

Registry values with large amounts of data are one way of hiding malicious executable data. The registry is persistent so the malware can remain through a reboot, but the malware is not on disk so is not detected by traditional AV.

See http://www.codereversing.com/blog/archives/261 for an explanation of how this works.

Rev 0.1 recursively dives through the registry on an online Windows system, scanning each of the five hives for any data greater than 20kb by default. You can adjust this by changing the "minsize" value in the source code.

Planned enhancements:
1. Change minsize to a command-line argument
2. Filter out known-good large registry values
3. Add support for analyzing offline registries
4. Add a "top n" function to report only the "n" largest data values
