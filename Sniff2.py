#This Tool Sniff's Out Packets Using Interface wlan0!
#It Prints The Packet Layer!
#More Will Be Added!
import time
import threading
import logging 
from threading import Thread
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from colorama import *
ICMP = Style.BRIGHT + Fore.RED + "ICMP: " + Style.RESET_ALL
TCP = Style.BRIGHT + Fore.MAGENTA + "TCP: " + Style.RESET_ALL
UDP = Style.BRIGHT + Fore.YELLOW + "UDP: " + Style.RESET_ALL
ARP = Style.BRIGHT + Fore.CYAN + "ARP: " + Style.RESET_ALL
Sniff = Style.BRIGHT + Fore.CYAN + "   _____       _  __  __    " + Style.RESET_ALL
Sniff1 = Style.BRIGHT + Fore.CYAN + "  / ____|     (_)/ _|/ _|  " + Style.RESET_ALL
Sniff2 = Style.BRIGHT + Fore.CYAN + " | (___  _ __  _| |_| |_   " + Style.RESET_ALL
Sniff3 = Style.BRIGHT + Fore.CYAN + "  \___ \| '_ \| |  _|  _|  " + Style.RESET_ALL
Sniff4 = Style.BRIGHT + Fore.CYAN + "  ____) | | | | | | | |    " + Style.RESET_ALL
Sniff5 = Style.BRIGHT + Fore.CYAN + " |_____/|_| |_|_|_| |_|    " + Style.RESET_ALL  
Instagram = Style.BRIGHT + Fore.CYAN + "       Made By @array.hf " + Style.RESET_ALL
SnapChat = Style.BRIGHT + Fore.CYAN + "       SnapChat:uhnou    " + Style.RESET_ALL
iMessage = Style.BRIGHT + Fore.CYAN + "       iMessage:sniff@rape.lol " + Style.RESET_ALL
Discord = Style.BRIGHT + Fore.CYAN + "       Discord:ricky#7123      " + Style.RESET_ALL                        
count = 0
print Sniff
print Sniff1
print Sniff2
print Sniff3
print Sniff4
print Sniff5
print Instagram
print SnapChat
print iMessage
print Discord
print 
print """
1.) Sniff UDP Packets
2.) Sniff TCP Packets
3.) Sniff ICMP Packets
4.) Sniff ARP Packets 
5.) Sniff All Packets"""
print                         
bby = raw_input("What Type Of Packet Do You Wanna Sniff -->  ")
if "1" in bby: 
    def pkthandler(pkt):
        global count
        if pkt.haslayer ("UDP"):
            print UDP + pkt[IP].src + " --> " + pkt[IP].dst
            count += 1
if "2" in bby:
    def pkthandler(pkt):
        global count
        if pkt.haslayer ("TCP"):
            print TCP + pkt[IP].src + " --> " + pkt[IP].dst
            count += 1 
if "3" in bby:
    def pkthandler(pkt):
        global count
        if pkt.haslayer ("ICMP"):
            print ICMP + pkt[IP].src + " --> " + pkt[IP].dst
            count += 1    
if "4" in bby:
    def pkthandler(pkt):
        global count
        if pkt.haslayer ("ARP"):
            print ARP + pkt.src + " --> " + pkt.dst
            count += 1
if "5" in bby:
    def pkthandler(pkt):
        global count
        if pkt.haslayer ("UDP"):
            print UDP + pkt[IP].src + " --> " + pkt[IP].dst
            count += 1
        if pkt.haslayer ("TCP"):
            print TCP + pkt[IP].src + " --> " + pkt[IP].dst
            count += 1 
        if pkt.haslayer ("ICMP"):
            print ICMP + pkt[IP].src + " --> " + pkt[IP].dst
            count += 1 
        if pkt.haslayer ("ARP"):
            print ARP + pkt.src + " --> " + pkt.dst
            count += 1       
def main():
    if "1" in bby:
        sniff(iface="wlan0", prn=pkthandler)  
        print "\n" + str(count) + " Packets Have Been Captured! "
    if "2" in bby:
        sniff(iface="wlan0", prn=pkthandler)
        print "\n" + str(count) + " Packets Have Been Captured! " 
    if "3" in bby:
        sniff(iface="wlan0", prn=pkthandler)  
        print "\n" + str(count) + " Packets Have Been Captured! "
    if "4" in bby:
        sniff(iface="wlan0", prn=pkthandler)  
        print "\n" + str(count) + " Packets Have Been Captured! "
    if "5" in bby:
        sniff(iface="wlan0", prn=pkthandler)
        print "/n" + str(count) + " Packets Have Been Captured! "               
if "__main__" in __name__:
    main()   
