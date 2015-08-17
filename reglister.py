# RegLister v0.2
# Source: https://github.com/dnlongen/RegLister
# Author: David Longenecker
# Author email: david@securityforrealpeople.com 
# Author Twitter: @dnlongen
# Explanation: http://securityforrealpeople.com/reglister

import winreg,sys,argparse

# Define suported parameters and defaut values
parser = argparse.ArgumentParser(description='Recursively scan a Windows registry and print keys and values with a large data content. Hiding executable files in the registry is a common malware technique; as such files tend to be larger than most normal registry data, RegLister helps locate potentially suspicious registry data.')
parser.add_argument('-c', '--computername', dest='computername', default='', help='Remote computername to connect; if not specified, the local registry will be used')
parser.add_argument('-m', '--minsize', default=20, type=int, help='Show all data larger than this; default 20KB')
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Display verbose error messages; this will show errors for registry values to which you do not have access')
parser.add_argument('-d', '--debug', dest='debug', action='store_true')
parser.set_defaults(verbose=False,debug=False)
args=parser.parse_args()
minsize=(args.minsize*1024)
verbose=args.verbose
computername=args.computername
if computername: computername = "\\\\" + computername
debug=args.debug

hives = ["HKEY_CURRENT_USER","HKEY_LOCAL_MACHINE","HKEY_USERS","HKEY_CLASSES_ROOT","HKEY_CURRENT_CONFIG"]

# Anything in the whitelist will be ignored, ragardless of the size of data content.
whitelist = [
  "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications\AppDB",
  "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\IconStreams",
  "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\PastIconsStream",
  "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\IconStreams",
  "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\PastIconsStream"
]

def ListValues(path,key):
  # ListValues will enumerate the *values* in a specific registry key, then obtain the size of the data in
  # each value. If the data contained is > minsize, ListValues will print out the path and the size of the data
  if debug: print("ListValues: " + path)
  i = 0
  value = ""
  try:
    while 1:
      # Infinite loop, aborted upon an error; in other words, loop until we runout of values to examine
      value = (winreg.EnumValue(key,i))
      if debug: print(path + "\\" + value[0] + " ("+ str(value[1]) + ") " + str(sys.getsizeof(value[1])))
      if not (path + "\\" + value[0]) in whitelist:
        if sys.getsizeof(value[1]) > minsize:
          print(path + "\\" + value[0] + ": " + str(sys.getsizeof(value[1])))
          # Hereis where we could writethe contents, or hash and check VT 
      i += 1
  except WindowsError as e:
    if not (e.errno == 22):
      if (verbose or debug): print("Error opening " + path + "[" + i + "]; " + str(e.errno) + ": " + e.strerror)
    pass
  return

def ListKeys(path,key):
  if debug: print("ListKeys: " + path)
  i = 0
  subkey = ""
  try:
    while 1:
      # Infinite loop, aborted upon an error; in other words, loop until we runout of subkeys to examine
      # Call ListValues first to examine any data values directly contained in this key
      # Then call ListKeys to recurse deeper
      subkey = winreg.EnumKey(key,i)
      if debug: print("subkey: " + subkey)
      ListValues(path + "\\" + subkey, winreg.OpenKey(key,subkey))
      if debug: print("Calling ListKeys with " + path +"\\" + subkey)
      ListKeys(path + "\\" + subkey, winreg.OpenKey(key,subkey))
      i += 1
  except WindowsError as e:
    if not (e.errno == 22):
      if (verbose or debug): print("Error opening " + path + "\\" + subkey + "; " + str(e.errno) + ": " + e.strerror)
    pass
  return

if __name__ == '__main__':
  if debug:
    print("Starting RegLister")
    print("Minsize: " + str(minsize))
    print("Computername: " + computername)
  for hive in hives:
    # Try this which each valid registry hive
    try:
      if debug: 
        if computername: print("Processing hive " + computername + "\\" + hive)
        else: print("Processing local registry hive " + hive)
      registry=winreg.ConnectRegistry(r"%s" % computername,getattr(winreg, hive))
      ListKeys(hive, winreg.OpenKey(registry,""))
    except OSError as e:
      if computername: print("Error opening " + computername + "\\" + hive)
      else: print("Error opening local registry hive " + hive)
      print("Error code: " + str(e.errno) + " (" + e.strerror + ")")
      if ((verbose or debug) and (e.errno==2 or e.errno==53)): 
        print("Perhaps you need to map a null session?")
        print("Is the remote registry service enabled on " + computername + "?")
        print("Is Windows firewall enabled on " + computername + "?")
        sys.exit()
      if ((verbose or debug) and e.errno==13): 
        print("Perhaps you need to map a null session?")
        pass