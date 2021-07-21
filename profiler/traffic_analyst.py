import pyshark
import argparse
import os
import socket
import re
import ipaddress
import numpy as np
from profiler.util import *
from bs4 import BeautifulSoup # scraper
import requests as r # for get page information

PRINT = True

# using globals since inspect packet function doesn't have any arguments

MIN_OCCURRENCE = 1 # Not interested in scanning or similar activities
ip_dict = {}
port_dict = {}
background_traffic = []
background_fields = ["icmpv6", "icmp", "mdns", "dns", "dhcpv6", "dhcp", "arp", "ntp"]
DNS_Mappings = {}
own_ip = None
excluded_ports = None

tcase = ""
ipsrc = ""
length = 0
id = 0
count = 0

FILE_NAME = ""

def finder_print(*args):
    global FILE_NAME
    module_print("[cnc-finder]",FILE_NAME, ":", *args)

def counter(packet=None):
    global count
#  packets_array.append(packet[0])
    count = count + 1


def is_background_traffic(pkt):
    global background_fields
    pkt_fields = dir(pkt)
    for field in background_fields:
        if field in pkt_fields:
            background_traffic.append(pkt)
            return True
    return False

def check_dns_address(pkt): # Exception for DNS packets
    if 'dns' in dir(pkt):
        dns_dir = dir(pkt.dns)
        for_test = int(pkt.dns.flags.hex_value) & 0x8001
        reply_status = int(pkt.dns.flags.hex_value) & 0x8003 # this means response and no reply in DNS
        if reply_status == 0x8003:
            return pkt.dns.qry_name
        elif for_test == 0x8000 and "a" in dns_dir and "qry_name" in dns_dir: # it's a response and no error
            # print(dir(pkt.dns))
            DNS_Mappings[pkt.dns.a] = pkt.dns.qry_name
            # print("qry_name",pkt.dns.qry_name,":",pkt.dns.a)    
    return None

# Taken from https://codingshiksha.com/python/python-3-alexa-ranking-web-scraping-bot-script-to-find-alexa-rank-of-website-every-1-minute-using-beautifulsoup4-library-full-project-for-beginners/
# this function gets the Alexa rank
def rank(domain):
    url = "https://www.alexa.com/siteinfo/" + domain
    respone = r.get(url) # get information from page
    soup = BeautifulSoup(respone.content,'html.parser')  
    for match in soup.find_all('span'): #remove all span tag
        match.unwrap()
    global_rank = soup.select('p.big.data') # select any p tag with big and data class
    res = None
    if global_rank:
        global_rank = str(global_rank[0])
        res = re.findall(r"([0-9,]{1,12})", global_rank) # find rank 
        if res:
            res = int(res[0])
    return(res) #return rank

def inspect_packet(pkt):
    counter(pkt)
    global ip_dict, port_dict, own_ip, excluded_ports, id, PRINT
    not_found_dns_addr = check_dns_address(pkt)
    if not_found_dns_addr:
        if not_found_dns_addr in ip_dict:
            ip_dict[not_found_dns_addr]["Total"] = ip_dict[not_found_dns_addr]["Total"] + 1
            ip_dict[not_found_dns_addr]["DNS_QUERIES"] = ip_dict[not_found_dns_addr]["DNS_QUERIES"] + 1
        else:
            ip_dict[not_found_dns_addr] = {"Total":1, "DNS_QUERIES":1}
    bg_pkt = is_background_traffic(pkt)
    if not bg_pkt:
        if 'tcp' in dir(pkt):
            if own_ip and pkt.ip.dst==own_ip:
                target = pkt.ip.src + ":" + pkt.tcp.srcport # the response should be also considered.
            else:
                target = pkt.ip.dst + ":" + pkt.tcp.dstport
            state = ""
            port_num = target.split(":")[1]
            if excluded_ports and port_num in excluded_ports:
                return # this port is not a candidate for CnCs
            if target not in ip_dict: # this is a new IP address contacted by port port_num
                if port_num in port_dict:
                    port_dict[port_num] +=1 # a new host of this port was contacted
                else:
                    port_dict[port_num] = 1 # the only host, we favor these
            if pkt.tcp.flags_reset=='1':
                # print(dir(pkt.tcp))
                state = "RST"
            elif pkt.tcp.flags_syn=='1':
                if pkt.tcp.flags_ack!="1":
                    state = "SYN"
                else:
                    return # don't need to take into account SYN ACK
            elif pkt.tcp.flags_fin=="1":
                state = "FIN" # FIN will later tell us if the conn was really a success
            else:
                state = "SUC" # ACK is success (handshake completed)
            if target in ip_dict:
                ip_dict[target]["Total"] = ip_dict[target]["Total"] + 1
                if state in ip_dict[target]:
                    ip_dict[target][state] = ip_dict[target][state] + 1
                else:
                    ip_dict[target][state]= 1
            else:
                ip_dict[target] = {"Total":1, state:1}
        # print(pkt)

def validate_ip_format(ip_str):
    ip_param = ip_str
    reg_exp = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if ":" in ip_str:
        li = ip_str.split(":")
        if len(li)>=2:
            ip_param = li[0]
    res = False
    try:
        m = re.match(reg_exp,ip_param)
        if m:
            res = True
    except:
        res = False
    return res

def generate_addr_list(addrs):
    addresses = []
    for addr in addrs:
        if validate_ip_format(addr):
            addresses.append(addr)
        else:
            v4Net = None
            addr_port = addr.split(":")
            if len(addr_port)!=2:
                finder_print(" port num is missing from", addr)
                return None
            try:
                v4Net = ipaddress.IPv4Network(addr_port[0])
                for ip in v4Net:
                    addresses.append(str(ip)+":"+addr_port[1])
            except:
                finder_print(" The address ",addr,"is not in acceptable formats")
                return None
    return addresses

# dict_ip is the find_CnC return value that is a list of IP tuples with {'Total': VALU1, 'SYN': VALUE2, 'SUC': VALUE3, 'RST': VALUE4} values
# returns a list of IP tuples with the weight of being a succesful CnC communication
def find_success(list_ip, target_ip=None,ratio_threshold=0):
    result = {}
    for ip in list_ip:
        if 'SUC' in ip[1] and 'RST' not in ip[1] and ("FIN" not in ip[1] or ip[1]['FIN']<=2): # FIN shouldn't occure at all but we tolerate 2 times because some Mirai are like this
            if target_ip and target_ip.split(":")[0]==ip[0].split(":")[0]:
                if 'SYN' in ip[1]: #self IP does not have SYN
                    return ip[1]['SYN']
                else:
                    return 0
            else:
                if 'SYN' in ip[1]: #self IP does not have SYN
                    result[ip[0]] = ip[1]['SYN']
    if not target_ip:
        sorted_res = sorted(result.items(), key=lambda kv: kv[1]['Total'], reverse=True)
        return sorted_res
    else:
        return None

# towardsdatascience.com: Function to Detection Outlier on one-dimentional datasets.
def find_outliers(freqs, THS=3): #TODO make sure it works for doubles.
    # a list to accumlate the indexes of outliers
    outliers = []

    # Set upper and lower limit to THS standard deviation
    data_std = np.std(freqs)
    finder_print(" STD:",data_std)
    data_mean = np.mean(freqs)
    finder_print(" MEAN:",data_mean)
    cut_off = data_std * THS
    #print(data_std,data_mean,cut_off)
    lower_limit  = data_mean - cut_off 
    upper_limit = data_mean + cut_off
    # Find outliers
    for i in range(len(freqs)):
        if freqs[i] <= lower_limit: # not interested in the upside freqs[i] > upper_limit
            outliers.append(i)
    return outliers

def find_cnc(pcap, ip=None, ports=None,PRINT=False,Alexa_ranking=-1):
    global FILE_NAME, ip_dict, port_dict, count, own_ip, excluded_ports, DNS_Mappings
    ip_dict.clear()
    background_traffic.clear()
    DNS_Mappings.clear()
    port_dict.clear()
    count = 0
    own_ip = ip
    excluded_ports = ports
    ports_added = []
    if not os.path.isfile(pcap):
        finder_print("Input is not a file ",str(pcap))
        return False
    else:
        if len(pcap)>100:
            FILE_NAME = pcap[100:]
        else:
            FILE_NAME = pcap
    cap = pyshark.FileCapture(pcap)
    cap.apply_on_packets(inspect_packet)
    dict_all = {}
    if PRINT:
        finder_print("Total: " + str(count))
        finder_print("background-Traffic: " + str(len(background_traffic)))
        finder_print("****Candidates****")
    for ip in ip_dict:
        shoud_be_added = False
        if "RST" in ip_dict[ip] and ip_dict[ip]["RST"]>MIN_OCCURRENCE: 
            shoud_be_added = True
        if "SYN" in ip_dict[ip] and ip_dict[ip]["SYN"]>MIN_OCCURRENCE:
            shoud_be_added = True
        if "SUC" in ip_dict[ip] and ip_dict[ip]["SUC"]>MIN_OCCURRENCE:
            shoud_be_added = True
        if "DNS_QUERIES" in ip_dict[ip]: # Single use of DNS could be indicative because activities like scanning are not based on DNS
            shoud_be_added = True
        if shoud_be_added:
            ip_port = ip.split(":")
            if len(ip_port)>1:  # it's not a DNS address
                if ip_port[1] not in ports_added:
                    ports_added.append(ip_port[1])
                    ip_dict[ip]["Score"] = (1.0 * ip_dict[ip]["Total"])/port_dict[ip_port[1]]
                else:
                    shoud_be_added = False
            else: # there's not port to consider
                ip_dict[ip]["Score"] = (1.0 * ip_dict[ip]["Total"])
            ipKey = ip_port[0]
            if ipKey in DNS_Mappings:
                ip_dict[ip]["DNS_Name"] = DNS_Mappings[ipKey]
            elif not validate_ip_format(ipKey): # it's a not found DNS
                ip_dict[ip]["DNS_Name"] = ipKey
            if Alexa_ranking>0 and "DNS_Name" in ip_dict[ip]:
                ranking = rank(ip_dict[ip]["DNS_Name"])
                if ranking and ranking<Alexa_ranking:
                    shoud_be_added = False
            if shoud_be_added:    
                dict_all[ip] = ip_dict[ip]
                if PRINT:
                    finder_print(str(ip)+"="+str(ip_dict[ip]))
    if PRINT:
        finder_print("***********")
    sorted_cncs = sorted(dict_all.items(), key=lambda kv: kv[1]['Score'], reverse=True)
    return sorted_cncs

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-output", type=str, help="Dumps the result in this csv file.", default="cnc_list.csv")
    parser.add_argument("-pcap", type=str, help="the pcap file", required=True)
    parser.add_argument("-myip", type=str, help="the ip of the infected machine to exclude", required=True)
    parser.add_argument("-ports", nargs='*', type=str, help="the ports to be excluded like 23 (attributed to other activities like scanning)")
    args = parser.parse_args()
    find_cnc(args.pcap, ip=args.myip, ports=args.ports)