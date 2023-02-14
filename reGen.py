 #!/usr/env/python3.10

"""
Name: reGen.py (report generator)
Author: Caleb Bryant
Date: 2023/02/11
Description: Inspired by Zach Branch's Escalator.py, this program is a command line tool meant to streamline the process of collecting information in a security incident.
"""

import sys, re, argparse
from ipaddress import ip_address
from Entities import *
from APIwrapper import *

# regex declarations
timestamp_regex = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
ip_regex = re.compile(r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
privateip_regex = re.compile(r'^(10\.([0-9]{1,3}\.[0-9]{1,3})|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}$')
url_regex = re.compile(r'^(http|https)://\S+$')
sha256_regex = re.compile(r'^[a-fA-F0-9]{64}$')
sha1_regex = re.compile(r'^[a-fA-F0-9]{40}$')
md5_regex = re.compile(r'^[a-fA-F0-9]{32}$')

# declaring parser
parser = argparse.ArgumentParser(description='Automate security incident report writing.')

# declaring parser arguments
parser.add_argument('name', type=str, help='Name of the triggering alert')
parser.add_argument('date', type=str, help='UTC date of the event in YYYY-MM-DD format')
parser.add_argument('time', type=str, help='UTC timestamp of the event in HH:MM:SS format')
parser.add_argument('-u', '--user', type=str, help='Username')
parser.add_argument('-H', '--host', type=str, help='Hostname')
parser.add_argument('-f', '--file', type=str, help='File name')
parser.add_argument('-p', '--path', type=str, help='File path')
parser.add_argument('-a', '--hash', type=str, help='File hash')
parser.add_argument('-s', '--srcip', type=str, help='Source IP address')
parser.add_argument('-d', '--destip', type=str, help='Source IP address')
parser.add_argument('-U', '--url', type=str, help='URL')
parser.add_argument('-D', '--domain', type=str, help='Domain name')
parser.add_argument('-j', '--jira', action='store_true', help='Create a Jira query link')
parser.add_argument('-v', '--verbose', action='count', help='Increase verbosity of the output')

args = parser.parse_args()

alertName = args.name
timestamp = "{} {}".format(args.date, args.time)
user = args.user
host = args.host
fileName = args.file
filePath = args.path
fileHash = args.hash
srcIp = args.srcip
destIp = args.destip
url = args.url
domain = args.domain
jira = args.jira
verbosity = args.verbose

# def gen_report():

try:
    if not re.match(timestamp_regex, timestamp):
        raise ValueError("Invalid timestamp format")

    if user:
        newUser = Entity("User", user)

    if host:
        newHost = Entity("Hostname", host)

    if fileName:
        newFileName = Entity("Filename, fileName")

    if filePath:
        newFilePath = Entity("Filepath", filePath)

    if fileHash:
        sha256_error, sha1_error, md5_error = (False, False, False)
        if not re.match(sha256_regex, fileHash):
            sha256_error = True
        if not re.match(sha1_regex, fileHash):
            sha1_error = True
        if not re.match(md5_regex, fileHash):
            md5_error = True
        if sha256_error and sha1_error and md5_error:
            raise ValueError("File hash does not match sha265, sha1, or md5 formats")
        hashType = "sha256" if not sha256_error else "sha1" if not sha1_error else "md5"
        newFileHash = FileHash(fileHash, hashType)
        if verbosity == 1:
            newFileHash.enrich()
        # elif verbosity > 1:
        #     fileHash.enrich()

    if srcIp:
        ipType = "private" if ip_address(srcIp).is_private else "public" # will throw a ValueError if not a valid IP address
        newSrcIp = IP_Address(srcIp, ipType)
        if verbosity == 1:
            srcIp.enrich()
        # elif verbosity > 1:
        #     srcIp.enrich()

    if destIp:
        ipType = "private" if ip_address(destIp).is_private else "public" # will throw a ValueError if not a valid IP address
        newDestIp = IP_Address(srcIp, ipType)
        # check if IP is public or private before proceding to save on API calls
        if verbosity == 1:
            destIp.enrich()
        # elif verbosity > 1:
        #     destIp.enrich()
        

    if url:
        if not re.match(url_regex, url):
            raise ValueError("Invalid URL")
        url = URL(url)
        if verbosity == 1:
            url.enrich()
        # elif verbosity > 1:
        #     ipAddress.enrich()

    if domain:
        # to do
        pass

    if jira:
        # to do: find out how the jira query urls are formatted
        pass
    
except ValueError as e:
    sys.exit(e.args)