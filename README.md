
# About (from the original)

Ioreth is a **very experimental** APRS bot. There are a lot of things to be
done yet, including writing the documentation. For now, you are welcome to
use it as you want.

Note that transmitting on the usual APRS ham bands requires (at least) an
Amateur Radio license and additional conditions and limitations for this
particular mode of operation may apply on your country or region. You MUST
ensure compliance with your local regulations before transmitting, but all
other uses are only subjected to the GNU GPLv3+ (see license bellow).

Connecting this program to the APRS-IS network also requires a license as
you will be, effectively, operating remote transmitters through the Internet.

# Updates to the version Wayne Spivak, KC2NJV created with full Store & Forward
# This document is a work-in-progress.

<b> Commentary:</b>

As most Hams are aware, APRS was developed as a broadcast and go system.  In other words, if you miss the beacon, bulletin or text message, you missed it.
The original concept of the APRSBOT was a mailing list, but still in line with the send once concept. 

This version enables Store & Forward (and the ability by user to turn it off).  It also permits the SysOp to configure length of time a message can be in the Store, how many attempts as well as automatic systemic rebroadcasts.  

This last issue was created since APRS-IS only clients (phones, tablets and computers) don't always propagate in the APRS universe.  Thus, if you wait for a callsign to be heard to trigger sending messages from the Store, they may never come.  The system attempts 1 time every six hours based on UTC.   It also abides by the rules for total number of attempts.


<b>Installation and Notes:</b>  

Read the requirements file.  I had to load 99% in a virtual environment and run the program in the same environment.  The replybot.service is configured that way.

Put everything in /opt/aprsbot.  I don't think there is anything hard-coded in Bot.py (some fallbacks), but everything is in aprsbot.conf.

Some other scripts, like the service scripts, the tatical_text_msg.py and tatical_beacon.py, at_aprs_send.sh and random_aprs_scheduler.sh (make exec) need some info customized. trim_audit_logs.py also need some slight modification.

The log.html file, (make it to your liking, maybe as a php file..) and check the aprsapi.service file to obtain the logs.  You will need to install gunicorn and probably nginx.

Add the following cron jobs 

     #send beacon
     
     */3 * * * * /usr/bin/python /opt/aprsbot/ioreth/tatical_beacon.py  >/dev/null 2>&1
     
     #Trim audit_log

     0 3 * * * /usr/bin/python3 /opt/aprsbot/trim_audit_logs.py

     #Run auto-random messages to your list:

     1 0 * * * /opt/aprsbot/random_aprs_scheduler.sh

     # Optional other meesages use this syntax:
     
     0 */2 * * * cd /opt/aprsbot; python -m ioreth.tatical_text_msg  <Your sending Callsign/Tatical Callsign> "MSG your message" >/dev/null 2>&1


<b>Addtional Changes to the Orginal:</b>

Logger provides timestamps

SQLite3 databases for users, blacklisted callsigns and admins (with timestamps), audit_log

Blacklist limited to Admins, is manually added and is normalized, i.e.; callsign AB2xyz will block all AB2xyx-xx.

Public logging via the DB, based on the full audit trail.  

As mentioned: Logging handled by gunicorn, a service is supplied (check paths). Api.py and basic HTML page supplied.  You should use nginx for the proxy between log.php and api.py.

Added code to prevent loopback (deduplication) from sent messages

Anyone sending HELP to an alias for the list will recieve a response, unless they are blacklisted.

Configurable in aprsbot.conf:
Added configurable Welcome message for new subscribers
Callsign, Callsign Alias, List Names, DB name.
Configurable Beacon text
Configurable Known Commands
Deduplication time value

Other items (some repeated):

Added a beacon (tatical_beacon.py) which will enable APRS-IS only devices to find your tactical callsign (add a cronjob @15min intervals).

Added a script to trim audit_log in SQLite3 db.  Just add a cron job.

Added a db to keep deduplication persistent over bot reboots.  

Relaybot.service to automatically start (on my system I had to run python in a virtual environment)

To create or delete ADMINS, I have remvoed this facility.  I suggest you use sqlite3 and use
a) To Add:
    "INSERT OR IGNORE INTO admins (callsign) VALUES (?)"
b) To Delete:
     "DELETE FROM admins WHERE callsign = ?"
     
<b>New/Changed Commands:</b>

<b>NOTE:</b> Commands are not case sensitive (given my radios, that would be insane :) )

CQ [space] [listname] [message] <-- listname is configured in APRSBOT and can be multiples

[<b>NOTE:</b> There is no automatic unsubscribe (concept is that this was made for Emergency Communications)

NetMSG or MSG or NetMRG/MRG (normal typos) [space] [message] <-- to distribute message to list

NETUSERS  <-- Last 10 list of users

NETCHECKOUT  <-- to leave the list.

BLACKLIST ADD/BLACKLIST DEL <-- needs Admin Privileges

SF-ON/SF-OFF  <-- Turns on (Default) or off of the Store and Forward system


# ToDo List:

I want to add some intelligence to the system:
a) Determine based on Last_heard method of transport whether to send the message via APRS-IS or RF
b) Ability to request WX with zip code/City just the way "Time" or "Version" commands are sent

# License (from the original)

Copyright (C) 2020  Alexandre Erwin Ittner, PP5ITT <alexandre@ittner.com.br>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.



# Contact information

Hacker:

Wayne Spivak (callsign: KC2NJV)

E-mail: <kc2njv@sbanetweb.com>

Web: <http://sbanetweb.com:8080>

The acutal coding was done by Gemini, Co-Pilot, ChatGPT and Perplexity AI.  I would not recommend using any of them given a multitude of issues from failure to comply with instructions, mission creep, rabbit holes (logic), and the list goes on...

Original Author:
Author: Alexandre Erwin Ittner   (callsign: PP5ITT)

Email: <alexandre@ittner.com.br>

Web: <https://www.ittner.com.br>
