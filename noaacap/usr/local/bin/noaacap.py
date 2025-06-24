#!/usr/bin/python3

## Author:  Dan Srebnick, K2IE
## License: BSD-2-Clause (/usr/local/share/noaacap/LICENSE)
## This program is called from aprx.
##
## See /usr/local/share/noaacap/CHANGELOG for change history
##
version = "1.5"

import sys
import pytz
import datetime
import dateutil.parser
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
import argparse

log = logging.getLogger('noaacap')
log.addHandler(JournalHandler(SYSLOG_IDENTIFIER='noaacap'))

if len(sys.argv) == 2 and sys.argv[1] == '-v':
   print("noaacap.py by K2IE, version " + version + "\n")
   print("A weather alert beacon exec for aprx >= 2.9 and Direwolf >= 1.3")
   print("Licensed under the BSD 2 Clause license")
   print("Copyright 2017-2025 by Daniel L. Srebnick\n")
   sys.exit(0)

# Command-line argument parsing
parser = argparse.ArgumentParser(description="noaacap.py - APRS Weather Alerts beacon exec for aprx & Dire Wolf")
parser.add_argument('--config', '-c',
                    help='Path to the configuration file (default: /etc/noaacap.conf)',
                    default='/etc/noaacap.conf')
parser.add_argument('--dbfile', '-d',
                    help='Path to the database file (default: /dev/shm/noaaconf.db)',
                    default='/dev/shm/noaaconf.db')
args = parser.parse_args()

# We need this function early in execution
def ErrExit():
   log.error("Exiting")
   print()
   exit(0)

conffile = args.config

if not os.path.isfile(conffile):
   log.error(conffile + " not found")
   ErrExit()

config = configparser.ConfigParser()

try:
   config.read(conffile)
except:
   log.error("Check " + conffile + " for proper [noaacap] section heading")
   ErrExit()

try:
   Logging = config.get('noaacap', 'Logging')
except:
   log.error("Check " + conffile + " for proper Logging value in [noaacap] section")
   ErrExit()

if Logging == '1':
   log.setLevel(logging.INFO)
elif Logging == '2':
   log.setLevel(logging.DEBUG)

log.info("Starting")

try:
   myTZ   = config.get('noaacap', 'myTZ')
except:
   log.error("Check " + conffile + " for proper myTZ value in [noaacap] section")
   ErrExit()

try:
   myZone = config.get('noaacap', 'myZone')
except:
   log.error("Check " + conffile + " for proper myZone value in [noaacap] section")
   ErrExit()

try:
  adjZone1 = config.get('noaacap', 'adjZone1')
except:
  adjZone1 = ''

try:
  adjZone2 = config.get('noaacap', 'adjZone2')
except:
  adjZone2 = ''

try:
   myResend = int(config.get('noaacap', 'myResend'))
except:
   log.error("Check " + conffile + " for proper myResend value in [noaacap] section")
   log.error("Try 0 (for no resend)")
   log.error("or 30 (for 1h if beacon cycle-size 2m)")
   ErrExit()

url = 'https://api.weather.gov/alerts/active.atom?zone=' + myZone

try:
   r = requests.get(url, timeout=2)
except requests.exceptions.Timeout:
   log.error("Timeout exception requesting " + url)
   ErrExit()

if r.status_code != 200:
   log.error(str(r.status_code) + " " + url)
   ErrExit()

soup = BeautifulSoup(r.text, 'xml')
entries = soup.find_all('entry')
count = len(entries)

dbfile = args.dbfile
if count == 0:
   log.info("Exiting - no events found")
   if os.path.isfile(dbfile):
      os.remove(dbfile)
   print()
   exit(0)

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
   EventEnd = EventEnd.rstrip('/')
   return ProductClass, Action, Office, Phenomena, Significance, ETN, \
      EventBegin, EventEnd

def move_entry(mylist,entry_val,entry_pos):
   z_index = mylist.index(entry_val)
   z_value = mylist.pop(z_index)
   mylist.insert(entry_pos,z_value)
   return mylist

hit = 0
for i in range(0, count):

   log.info("Processing entry: " + str(i + 1) + " of " + str(count))
   if i == 0:
       alerts = db.DB()
       alerts.open(dbfile, "Alerts", db.DB_HASH, db.DB_CREATE)
       if myResend > 0:
          resend = db.DB()
          resend.open(dbfile, "Resend", db.DB_HASH, db.DB_CREATE)
       pp = db.DB()
       pp.open(ppmap, None, db.DB_HASH, db.DB_RDONLY)

   updated = entries[i].updated.string

   if entries[i].status.string == "Actual":

      # Retrieve link for entry i
      url = entries[i].id.string + ".cap"

      try:
         r = requests.get(url, timeout=2)
      except requests.exceptions.Timeout:
         log.error("Timeout exception requesting " + url)
         ErrExit()

      if r.status_code != 200:
         log.error(str(r1.status_code) + " " + url)
         ErrExit()

      soup = BeautifulSoup(r.text, 'xml')

      VTEC = ''
      for j in soup.select('parameter'):
         if j.find('valueName').text == 'VTEC':
            VTEC = j.find('value').text

      log.debug("VTEC String: " + VTEC)

      # Parse P-VTEC string and make sure this is an operational ProductClass

      try:
         ProductClass, Action, Office, Phenomena, Significance, ETN, \
           EventBegin, EventEnd = vtecparse(VTEC)
      except:
         log.debug("VTEC parse failed")
         continue                               #Loop if error parsing P-VTEC

      if ProductClass != "/O":                  #Loop if not operational
         continue

      EventEnd = "20" + EventEnd

      # Is alert expired?
      now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
      # Fix exit on exp = '000000T0000Z'
      try:
         exp = dateutil.parser.parse(EventEnd)
      except:
         exp = now

#      log.debug('Time Now:   ' + datetime.datetime.strftime(now,"%y-%m-%d %H:%M"))
#      log.debug('Expiration: ' + datetime.datetime.strftime(exp,"%y-%m-%d %H:%M"))

      if now > exp:
         log.debug("Alert Expired")
         continue
      else:
         log.debug("Alert Valid")

      id = bytes(str(Office + Phenomena + Significance + ETN), 'utf-8')

#      log.debug("ID: " + id.decode('utf-8'))

      # Do we have this alert?
      if id in alerts:
         # Is the updated time unchanged?
#         log.debug('ID found in alerts.  Now compare last updated time.')
         if alerts[id].decode('utf-8') == updated:
            log.debug(id.decode('utf-8') + " " + updated + " has already been sent")
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

      alerts.put(id, updated.encode('utf-8'))

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

      zcs_discrete = []
      for j in soup.select('area'):
         for k in j.select('geocode'):
            if (k.find('valueName').text == 'UGC'):
               addzcs = k.find('value').text
               zcs_discrete.append(addzcs)

      # This handles messages found to contain empty UGC list
      if zcs_discrete == []:
         log.debug('No UGC list in message')
         continue

      zcs = ''
      sorted_zcs = (sorted(zcs_discrete))

      # Move myZone to first position in case of truncation
      if myZone in sorted_zcs:
         move_entry(sorted_zcs,myZone,0)
         log.debug("myZone found in sorted zcs and moved to index 0")

      # Move adjacent zones, if present, after myZone
      adjZone2Index = 1
      if adjZone1 != '' and adjZone1 in sorted_zcs:
         adjZone2Index = 2
         move_entry(sorted_zcs,adjZone1,1)
         log.debug("adjZone1 found in sorted zcs and moved to index 1")

      if adjZone2 != '' and adjZone2 in sorted_zcs:
         move_entry(sorted_zcs,adjZone2,adjZone2Index)
         log.debug("adjZone2 found in sorted zcs and moved to index " + str(adjZone2Index))

      prev_item   = ''
      prev_prefix = ''
      prev_suffix = ''
      next_item   = ''
#      next_prefix = ''
      next_suffix = ''

      k = 0
      for j in sorted_zcs:
         k += 1
         curr_item = j

         try:
            next_item = sorted_zcs[k]
         except:
            next_item = ''
         if next_item != '':
#            next_prefix = next_item[0:3]
            next_suffix = next_item[3:6]
            i_next_suffix = int(next_suffix)

         curr_prefix = curr_item[0:3]
         curr_suffix = curr_item[3:6]
         i_curr_suffix = int(curr_suffix)
         i_curr_plus1 = i_curr_suffix + 1

         # Always print entire first item
         if k == 1:
            zcs = curr_item
         # Did prefix change?
         elif prev_prefix != curr_prefix:
            zcs = zcs + "-" + curr_item
         # Current suffix is 1 more than previous
         elif i_prev_plus1 == i_curr_suffix:
            if i_next_suffix != i_curr_plus1:
               zcs = zcs + ">" + curr_suffix
         # Current suffix is not 1 more than previous
         elif i_prev_plus1  != i_curr_suffix:
            zcs = zcs + "-" + curr_suffix
         else:
            log.error("Unexpected condition during zcs compression")
            ErrExit()

         # For debugging only
         # print (zcs)

         prev_item     = curr_item
         prev_prefix   = curr_prefix
         prev_suffix   = curr_suffix
         i_prev_suffix = int(prev_suffix)
         i_prev_plus1  = i_prev_suffix + 1

      log.debug("ZCS Value: " + zcs)
      type =  pp[bytes(Phenomena, 'utf-8')].decode('utf-8')

      if Action == "CAN":
         event = "CANCL"
      else:
         event = sg[Significance]

      hit = 1
      message = exputc + "z," + type + "," + zcs
      log.info("Msg: " + message)

      # Make sure message does not exceed 67 chars.  If it does, trim it.

      n = 0
      while len(message) > 67:
         n = zcs.rfind('-')
         zcs = zcs[0:n]
         message = exputc + "z," + type + "," + zcs

      if n > 0:
         log.info("Truncated Msg: " + message)

      line = "{" + t + "00"
      print(":NWS_" + event + ":" + message + line)
      if myResend > 0:
         resend[id] = bytes(str(myResend), 'utf-8')

      break

if hit == 0:
   print()

log.info("Exiting")
exit(0)
