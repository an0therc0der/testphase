import argparse
import winreg
from datetime import datetime, timedelta
import struct
import io

"""
This code is designed to query an active Windows Registry for key values and artifacts that
investigators may find useful. This code can be used to gather a rudimentary baseline of a 
registry or to hunt for abnormal keys and values within certain registries on a LIVE system.

Usage: LiveRegistryEnumeration.py [--hive $VAR1] [--wireless $VAR2] [--usb $VAR3] [--shimcache $VAR4]

"""
#Setup the command line arguments and help messages
parser = argparse.ArgumentParser(description="Live Registry Analysis:\nThis program provides some options for quick registry analysis to include Run Key Analysis, Wireless Network listings, USB information,and SHIM CACHE information.")
parser.add_argument('--hive', type=str, help='Display Run Keys. Options are: \'HKLM\', \'HKCU\', or \'Both\'')
parser.add_argument('-w', '--wireless', help='List Wireless Networks(Admin)', action="store_true")
parser.add_argument('-u', '--usb', help='List USB Devices', action="store_true")
parser.add_argument('--shimcache', type=int, help='(Experimental) Show logged data starting at given number of days ago.')
args = parser.parse_args()

def checkRunKeys(hive, name):
	#Check the Run and RunOnce keys in the given Hive and print results to screen
	#Results will be in the form 'Program Name: Program Path of Execution'
	keys = ['SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce']
	for k in keys:
		checkKey = winreg.CreateKey(hive, k)
		print ("Attempting enumeration of {0}\\{1}".format(name, k))
		print ("--- Program Name: Command Line")
		numValues = winreg.QueryInfoKey(checkKey)[1]
		if numValues > 0:
		  for index in range(numValues):
			  nameKey = winreg.EnumValue(checkKey, index)
			  print ("--- {0}: {1}".format(nameKey[0], nameKey[1]))
		  print ("Key Complete\n")
		else:
			print ("No Values in this Key\n")


def wirelessNetworks():
	#Check for all recorded connections to wireless networks and print results to the screen
	#Results will be in the form 'DNS Name: SSID'
	print ("Attempting enumeration of HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged")
	print ("--- DNS Suffix: SSID")
	checkKey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged')
	numValues = winreg.QueryInfoKey(checkKey)[0]
	if numValues > 0:
		for index in range(numValues):
			nameKey = winreg.EnumKey(checkKey, index)
			trueKey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\' + nameKey)
			DnsSuffix = winreg.EnumValue(trueKey, 3)
			FirstNetwork = winreg.EnumValue(trueKey, 4)
			print ("--- {0}: {1}".format(DnsSuffix[1], FirstNetwork[1]))
		print ("No additional Wireless Network Connections Found\n")
	else:
		print ("No Values in this Key\n")

def usbDevices():
	#Check for all recorded USB Devices that have connected to the system and print results to the screen
	#Results will be in the form 'Last Key Modification Date(UTC) - Friendly Name: ContainerID'
	print ("Attempting enumeration of USB Storage Devices")
	print ("--- Date First Connected(UTC) - Friendly Name: ContainerID")
	checkKey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Enum\\USBSTOR')
	numValues = winreg.QueryInfoKey(checkKey)[0]
	if numValues > 0:
		for index in range(numValues):
			nextKey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\' + winreg.EnumKey(checkKey, index))
			trueKey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\' + winreg.EnumKey(checkKey, index) + '\\' + winreg.EnumKey(nextKey, 0))
			#For some reason, some keys index values differently. We must iterate through all values to guarantee accuracy as a result.
			for value in range(winreg.QueryInfoKey(trueKey)[1]):
				curValue = winreg.EnumValue(trueKey, value)[0]
				nanoseconds = winreg.QueryInfoKey(trueKey)[2]
				if curValue == 'ContainerID':
					ContainerID = winreg.EnumValue(trueKey, value)
				elif curValue == 'FriendlyName':
					FriendlyName = winreg.EnumValue(trueKey, value)
			print ("--- {2} - {0}: {1}".format(FriendlyName[1], ContainerID[1], translateTime(nanoseconds)))
		print ("No additional devices found in USBSTOR\n")
	else:
		print ("No values in this key.")

def readShimCache(daysOfData):
	#Check for all programs recorded in the App Compatibility Cache (shim cache).
	#Results are in the form: Modification date : Path
	#What about execution flag?
	print ("(Experimental) Attempting enumeration of the SHIM Cache (Experimental)")
	print ("--- UTC Modification Time : Path")
	try:
	  checkKey = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache')
	except:
	  print ("Shim Cache not in expected Key. Other Keys and OS Version Support under development.\n")
	entrylist = []
	shim = winreg.EnumValue(checkKey, 0)[1]
	cache_data = shim[0x34:]
	data = io.BytesIO(cache_data)
	while data.tell() < len(cache_data):
		header = data.read(12)
		magic, crc32_hash, entry_len = struct.unpack('<4sLL', header)
		entry_data = io.BytesIO(data.read(entry_len))
		path_len = struct.unpack('<H', entry_data.read(2))[0]
		if path_len == 0:
			path = 'None'
		else:
			path = entry_data.read(path_len).decode('utf-16le', 'replace').encode('utf-8')
		low_datetime, high_datetime = struct.unpack('<LL', entry_data.read(8))
		adjustedTimes = (high_datetime << 32) | low_datetime
		#Windows uses January 1, 1601 as start time. Get number of microseconds from then to given number of days ago.
		timeRange = (timedelta(days=(152539-daysOfData)).total_seconds()) * 1000000
		#Only add entries from the past 60 days for now.
		if adjustedTimes / 10 > timeRange:
			row = [adjustedTimes, path.decode()]
			entrylist.append(row)
		else:
			continue
  #Need to sort dates appropriately as time-order is not maintained in the cache
	return sorted(entrylist)


def translateTime(nanoseconds):
	#Windows timestamps are number of 100ns since January 1st, 1601. This function translates time to make it more readable.
	return format(datetime(1601,1,1) + timedelta(microseconds=nanoseconds/10), '%d %B %Y %H:%M:%S')

def main():
	if args.hive is None and not args.wireless and not args.usb and args.shimcache is None:
		print ("No options given! Add -h to the command to display options!\n")
	else:
		if args.hive is not None:
			if args.hive.upper() in ("HKLM", "HKCU", "BOTH"):
				print ("--------------RUN KEYS--------------")
				if args.hive.upper() == "HKLM":
					checkRunKeys(winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE")
				elif args.hive.upper() == "HKCU":
					checkRunKeys(winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER")
				elif args.hive.lower() == "both":
					checkRunKeys(winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE")
					checkRunKeys(winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER")
			else:
				print ("Unrecongnized Choice for HIVE: \"{}\" is not valid.\n".format(args.hive))
		if args.wireless:
			print ("--------------WIRELESS NETWORK CONNECTIONS--------------")
			try:
				wirelessNetworks()
			except PermissionError:
				print ("You must be admin to check this key.\n")
		#elif args.wireless.lower() != 'no':
		  #print ("Unrecongnized Choice for Wireless: \"{}\" is not valid.\n".format(args.wireless))
		if args.usb:
			print ("--------------USB DEVICES--------------")
			usbDevices()
		#elif args.usb.lower() != "no":
		  #print ("Unrecongnized Choice for USB: \"{}\" is not valid.\n".format(args.wireless))
		if args.shimcache is not None:
			print ("--------------SHIM CACHE DATA--------------")
			results = readShimCache(args.shimcache)
			for entry in results:
				if entry[0] == 0:
					entry[0] = "No Timestamp - Unknown"
				else:
					entry[0] = translateTime(entry[0])
				print ("--- {0} : {1}".format(entry[0], entry[1]))
			print ("End of SHIM Cache Information\n")
	print ("Execution Complete")

if __name__ == "__main__":
  main()