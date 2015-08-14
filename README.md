# RegLister
Recurse through a registry, identifying values with large data
Written by David Longenecker (Twitter: @dnlongen)

Registry values with large amounts of data are one way of hiding malicious executable data. The registry is persistent so the malware can remain through a reboot, but the malware is not on disk so is not detected by traditional AV.

See http://www.codereversing.com/blog/archives/261 for an explanation of how this works.

Rev 0.1 recursively dives through the registry on an online Windows system, scanning each of the five hives for any data greater than 20kb by default. You can adjust this by changing the "minsize" value in the source code.

Supported args:
1. --minsize: size, in KB, of the registry data you are interested in. Any value containing data greater in size than this argument will be displayed.
2. -v, --verbose: Display verbose error messages. By default, "Access denied" and "File not found" errors are suppressed; this will show those messages.

Planned enhancements:
1. Filter out known-good large registry values
2. Add support for analyzing offline registries
3. Add a "top n" function to report only the "n" largest data values
