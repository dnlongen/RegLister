# RegLister v0.1
# Source: https://github.com/dnlongen/RegLister
# Author: David Longenecker (Twitter: @dnlongen)

import winreg,sys

debug=False
minsize = 20480 # default to 20 KB
hives = ["HKEY_CURRENT_USER","HKEY_LOCAL_MACHINE","HKEY_USERS","HKEY_CLASSES_ROOT","HKEY_CURRENT_CONFIG"]

def ListValues(path,key):
  if debug: print("ListValues: " + path)
  i = 0
  value = ""
  try:
    while 1:
      value = (winreg.EnumValue(key,i))
      if debug: print(path + "\\" + value[0] + " ("+ str(value[1]) + ") " + str(sys.getsizeof(value[1])))
      if sys.getsizeof(value[1]) > minsize:
        print(path + "\\" + value[0] + ": " + str(sys.getsizeof(value[1])))
      i += 1
  except WindowsError as e:
    if not (e.errno == 22):
      print("Error opening " + path + "[" + i + "]; " + str(e.errno) + ": " + e.strerror)
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
      print("Error opening " + path + "\\" + subkey + "; " + str(e.errno) + ": " + e.strerror)
    pass
  return

for hive in hives:
  if debug: print("Processing hive " + hive)
  ListKeys(hive, winreg.OpenKey(getattr(winreg, hive),""))
