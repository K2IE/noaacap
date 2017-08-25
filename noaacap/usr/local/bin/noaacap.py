#!/usr/bin/python

## Author:  Dan Srebnick, K2DLS
##
## Version: 0.4
## Release: August 24, 2017
##	    Switched to compressed zcs to improve capacity
##	    Improved messsage + \n length check
##
## Version: 0.3
## Release: August 22, 2017
## Changes: Implement NWS-CANCL messages, implement DB id consisting of
##           Office + Phenomena + Significance + ETN 
##
## Version: 0.2
## Release: August 19, 2017
## Changes: Make sure message + \n does not exceed 67 chars
##
## Version: 0.1
## Release: August 7, 2017
##
## License: BSD-2-Clause (/usr/local/share/noaacap/license.txt)
##
## This program is called from aprx.
##

import pytz, datetime
import string
import requests
from bs4 import BeautifulSoup
import bsddb
import os
import ConfigParser
import re

config = ConfigParser.ConfigParser()

try:
   os.path.isfile('/etc/noaacap.conf')
except:
   exit("\nError: /etc/noaacap.conf not found\n")
else:
   config.read('/etc/noaacap.conf')

myTZ   = config.get('noaacap', 'myTZ')
myZone = config.get('noaacap', 'myZone')

def aprstime(timestr,TZ):
   local = pytz.timezone (TZ)
   naive = datetime.datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%S")
   local_dt = local.localize(naive, is_dst=None)
   utc_dt = local_dt.astimezone (pytz.utc)
   return utc_dt.strftime ("%d%H%M")

def vtecparse(value):
   line = value.split("\n")[0]
   ProductClass, Action, Office, Phenomena, Significance, ETN, DTGroup = \
      line.split('.')
   EventBegin, EventEnd = DTGroup.split('-')
   return ProductClass, Action, Office, Phenomena, Significance, ETN, \
      EventBegin, EventEnd

def capchildren(children):
   k = None
   list = {}
   for tag in children:
      if tag.name == 'valueName':
         k = tag.string
      elif tag.name == 'value':
         list[k] = tag.string
   return list

def parsezcs(zcs):
   zonelist = set()
   inprogress = 0
   newprefix = 1
   for z in range(0, len(zcs)):
      if not inprogress:
         zone = ''
         inprogress = 1
      if re.match('[A-Z]',zcs[z]):
         if newprefix == 1:
            prefix = ''
            newprefix = 0
         prefix = prefix + zcs[z]
      if re.match('[0-9]',zcs[z]):
         zone = zone + zcs[z]
      if zcs[z] == '>':
         zonelist.add(prefix + zone)
         inprogress = 0
         endzone = zcs[z+1:z+4]
         z = z + 3
         startzone = int(zone) + 1
         endzone = int(endzone)
         for y in range(startzone, endzone):
            zonelist.add(prefix + str(y).zfill(3))
      elif zcs[z] == '-':
         zonelist.add(prefix + zone)
         inprogress = 0
         if re.match('[A-Z]',zcs[z+1]):
            newprefix = 1
   if inprogress:
      zonelist.add(prefix + zone)
   return zonelist

sg = {"W":"WARN ","A":"WATCH","Y":"ADVIS","S":"STMNT","F":"4CAST",
     "O":"OUTLK","N":"SYNOP"}

url = 'https://alerts.weather.gov/cap/wwaatmget.php?x=' + myZone + '&y=0'
try: 
   r = requests.get(url)
except:
   exit('\n')

soup = BeautifulSoup(r.text, 'xml')
entries = soup.find_all('entry')
count = len(entries)

dbfile = '/dev/shm/noaacap.db'
ppmap = '/usr/local/share/noaacap/ppmap.db'

hit = 0
for i in range(0, count):

   if ("no active" in entries[i].title.string):
      if os.path.isfile(dbfile):
         os.remove(dbfile)
      break
   else:
      if i == 0:
         alerts = bsddb.hashopen(dbfile,'c')
         pp     = bsddb.hashopen(ppmap,'r')

   updated = str(entries[i].updated.string)

   if (entries[i].status.string == "Actual"):

      # Parse P-VTEC string and make sure this is an operational ProductClass
      VTEC = capchildren(entries[i].parameter.children)
      try:
         ProductClass, Action, Office, Phenomena, Significance, ETN, \
           EventBegin, EventEnd = vtecparse(VTEC['VTEC'].string)
         if (ProductClass <> "/O"):		#Loop if not operational
            continue
      except:
         continue				#Loop if error parsing P-VTEC

      id = str(Office + Phenomena + Significance + ETN)

      if alerts.has_key(id):
         if alerts[id] == updated:
            continue
   
      alerts[id] = updated

      effutc = aprstime(entries[i].effective.string[0:-6],myTZ)
      exputc = aprstime(entries[i].expires.string[0:-6],myTZ)

      # Compress effective time to 3 byte

      dd = int(effutc[0:2])
      hh = int(effutc[2:4])
      mm = int(effutc[4:6])

      t = ''
      for s in (dd, hh, mm):
         if 0 <= s <= 9:
            t = t + chr(s+48)
         elif 10 <= s <= 35:
            t = t + chr(s+55)
         elif 36 <= s <= 61:
            t = t + chr(s+61)

      # Pull specific alert to get compressed UGC zones
      try:
         rs = requests.get(entries[i].id.string)
      except:
         exit('\n')

      soup2 = BeautifulSoup(rs.text, 'xml')
      parms = soup2.find_all('parameter')
      j = len(parms)
      for j in range(0, len(parms)):
         if parms[j].valueName.string == 'UGC':
            zcs = parms[j].value.string

      type =  pp[str(Phenomena)]
      event = sg[Significance]

      if Action == "CAN":
         event = "CANCL"

      hit = 1
      suffix = exputc + "z," + type + "," + zcs + "{" + t + "00"

      # Make sure message does not exceed 67 chars (66 + newline)
      # If it does, trim it.  Also be certain that myZone
      # is included in the trimmed zcs.
      while len(suffix) > 66:
         if not myZone in parsezcs(zcs):
            zcs = myZone + "-" + zcs
            suffix = exputc + "z," + type + "," + zcs + "{" + t + "00"
         n = zcs.rfind('-')
         zcs = zcs[0:n]
         suffix = exputc + "z," + type + "," + zcs + "{" + t + "00"
         
      print ":NWS_" + event + ":" + suffix
    
      break

if (hit == 0):
   print
