#!/usr/bin/python3

## Author:  Dan Srebnick, K2DLS
## License: BSD-2-Clause (/usr/local/share/noaacap/LICENSE)
## This program is called from aprx.
##
## See /usr/local/share/noaacap/CHANGELOG for change history
##
version = "0.7"

import sys
import pytz
import datetime
import string
import requests
from bs4 import BeautifulSoup
from bsddb3 import db
from os import remove
import os.path
import configparser
import re
import logging
from systemd.journal import JournalHandler

log = logging.getLogger('noaacap')
log.addHandler(JournalHandler(SYSLOG_IDENTIFIER='noaacap'))
log.setLevel(logging.DEBUG)
log.info("Starting")

if len(sys.argv) == 2 and sys.argv[1] == '-v':
   print("noaacap.py by K2DLS, version " + version + "\n")
   print("A weather alert beacon exec for aprx >= 2.9")
   print("Licensed under the BSD 2 Clause license")
   print("Copyright 2017 by Daniel L. Srebnick\n")
   sys.exit(0)

# We need this function early in execution
def Exiting():
   log.info("Exiting")
   print()
   exit(0)

conffile = '/etc/noaacap.conf'

if not os.path.isfile(conffile):
   log.error(conffile + " not found")
   Exiting()

config = configparser.ConfigParser()

try:
   config.read(conffile)
except:
   log.error("Check " + conffile + " for proper [noaacap] section heading")
   Exiting()

try:
   myTZ   = config.get('noaacap', 'myTZ')
except:
   log.error("Check " + conffile + " for proper myTZ value in [noaacap] section")
   Exiting()

try:
   myZone = config.get('noaacap', 'myZone')
except:
   log.error("Check " + conffile + " for proper myZone value in [noaacap] section")
   Exiting()

try:
   myResend = int(config.get('noaacap', 'myResend'))
except:
   log.error("Check " + conffile + " for proper myResend value in [noaacap] section")
   log.error("Try 0 (for no resend)")
   log.error("or 30 (for 1h if beacon cycle-size 2m)")
   Exiting()

url = 'https://alerts.weather.gov/cap/wwaatmget.php?x=' + myZone + '&y=0'

r = requests.get(url)
if r.status_code != 200:
   log.error(str(r.status_code) + " " + url)
   Exiting()

soup = BeautifulSoup(r.text, 'xml')
entries = soup.find_all('entry')
count = len(entries)

dbfile = '/dev/shm/noaacap.db'
ppmap = '/usr/local/share/noaacap/ppmap.db'

sg = {"W":"WARN ","A":"WATCH","Y":"ADVIS","S":"STMNT","F":"4CAST",
     "O":"OUTLK","N":"SYNOP"}

# Define functions used in the for loop
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

hit = 0
for i in range(0, count):

   if ("no active" in entries[i].title.string):
      if os.path.isfile(dbfile):
         os.remove(dbfile)
      break
   else:
      if i == 0:
          alerts = db.DB()
          alerts.open(dbfile, "Alerts", db.DB_HASH, db.DB_CREATE)
          if myResend > 0:
             resend = db.DB()
             resend.open(dbfile, "Resend", db.DB_HASH, db.DB_CREATE)
          pp = db.DB()
          pp.open(ppmap, None, db.DB_HASH, db.DB_RDONLY)

   updated = entries[i].updated.string

   if (entries[i].status.string == "Actual"):

      # Parse P-VTEC string and make sure this is an operational ProductClass
      VTEC = capchildren(entries[i].parameter.children)
      try:
         ProductClass, Action, Office, Phenomena, Significance, ETN, \
           EventBegin, EventEnd = vtecparse(VTEC['VTEC'].string)
         if (ProductClass != "/O"):		#Loop if not operational
            continue
      except:
         continue				#Loop if error parsing P-VTEC

      id = bytes(str(Office + Phenomena + Significance + ETN), 'utf-8')

      # Do we have this alert?
      if alerts.has_key(id):
         # Is the updated time unchanged?
         if alerts[id].decode('utf-8') == updated:
            log.debug(id.decode('utf-8') + " " + updated + " found")
            # Is resend behavoir desired?
            if myResend > 0:

               try:
                  recount = int(resend[id].decode('utf-8')) - 1
               except:
                  resend[id] = bytes(str(myResend), 'utf-8')
                  recount = int(resend[id].decode('utf-8')) - 1

               if recount > 0:
                  resend[id] = bytes(str(recount), 'utf-8')
                  log.debug(id.decode('utf-8') + " resend in " + str(recount) +
                     " iterations")
                  continue
            else:
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
      rs = requests.get(entries[i].id.string)
      if rs.status_code != 200:
         log.error(str(rs.status_code) + " " + rs)
         Exiting()

      soup2 = BeautifulSoup(rs.text, 'xml')
      parms = soup2.find_all('parameter')
      j = len(parms)
      for j in range(0, len(parms)):
         if parms[j].valueName.string == 'UGC':
            zcs = parms[j].value.string

      type =  pp[bytes(Phenomena, 'utf-8')].decode('utf-8')

      if Action == "CAN":
         event = "CANCL"
      else:
         event = sg[Significance]

      hit = 1
      message = exputc + "z," + type + "," + zcs
      log.info("Msg: " + message)

      # Make sure message does not exceed 67 chars.  If it
      # does, trim it.  Also be certain that myZone is included
      # included in the trimmed zcs.
	
      n = 0
      while len(message) > 67:
         n = zcs.rfind('-')
         zcs = zcs[0:n]
         message = exputc + "z," + type + "," + zcs
         if not myZone in parsezcs(zcs):
            zcs = myZone + "-" + zcs
            message = exputc + "z," + type + "," + zcs

      if n > 0:
         log.info("Truncated Msg: " + message)

      line = "{" + t + "00"
      print(":NWS_" + event + ":" + message + line)
      if myResend > 0:
         resend[id] = bytes(str(myResend), 'utf-8')
    
      break

if (hit == 0):
   print()

log.info("Exiting")
