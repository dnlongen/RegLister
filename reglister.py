# RegLister v0.1
# Source: https://github.com/dnlongen/RegLister
# Author: David Longenecker (Twitter: @dnlongen)

import winreg,sys

import argparse
parser = argparse.ArgumentParser(description='Recursively scan a Windows registry and print the values with the largest data.')
parser.add_argument('--minsize', default=20, type=int, help='Show all data larger than this; default 20KB')
parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Display verbose error messages; this will show errors for registry values to which you do not have access')
parser.set_defaults(verbose=False)
args=parser.parse_args()
minsize=(args.minsize*1024)
verbose=args.verbose

debug=False
#minsize = 20480 # default to 20 KB
hives = ["HKEY_CURRENT_USER","HKEY_LOCAL_MACHINE","HKEY_USERS","HKEY_CLASSES_ROOT","HKEY_CURRENT_CONFIG"]
whitelist = [
  "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications\AppDB",
  "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\IconStreams",
  "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\PastIconsStream",
  "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\IconStreams",
  "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\PastIconsStream"
]

def ListValues(path,key):
  if debug: print("ListValues: " + path)
  i = 0
  value = ""
  try:
    while 1:
      value = (winreg.EnumValue(key,i))
      if debug: print(path + "\\" + value[0] + " ("+ str(value[1]) + ") " + str(sys.getsizeof(value[1])))
      if not (path + "\\" + value[0]) in whitelist:
        if sys.getsizeof(value[1]) > minsize:
          print(path + "\\" + value[0] + ": " + str(sys.getsizeof(value[1])))
      i += 1
  except WindowsError as e:
    if not (e.errno == 22):
      if verbose: print("Error opening " + path + "[" + i + "]; " + str(e.errno) + ": " + e.strerror)
    pass
  return

def ListKeys(path,key):
  if debug: print("ListKeys: " + path)
  i = 0
  subkey = ""
  try:
    while 1:
      subkey = winreg.EnumKey(key,i)
      if debug: print("subkey: " + subkey)
      ListValues(path + "\\" + subkey, winreg.OpenKey(key,subkey))
      if debug: print("Calling ListKeys with " + path +"\\" + subkey)
      ListKeys(path + "\\" + subkey, winreg.OpenKey(key,subkey))
      i += 1
  except WindowsError as e:
    if not (e.errno == 22):
      if verbose: print("Error opening " + path + "\\" + subkey + "; " + str(e.errno) + ": " + e.strerror)
    pass
  return

if __name__ == '__main__':
  for hive in hives:
    if debug: print("Processing hive " + hive)
    ListKeys(hive, winreg.OpenKey(getattr(winreg, hive),""))
