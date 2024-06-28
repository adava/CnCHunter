import pyshark
import argparse
import os
import socket
import re
import ipaddress
import numpy as np
if __package__==None:
    from config_params import *
    from util import *
else:
    from .config_params import *
    from .util import *
    
from bs4 import BeautifulSoup # scraper
import requests as r # for get page information

CLIENT = 1
SERVER = 2
BUFFER_SIZE = 40
Client_str = "CLIENT"
Server_str = "SERVER"
Concat_char = "_"
MSG_SEP = "."

PRINT = False

def pattern_print(*args):
    global FILE_NAME, PRINT
    if PRINT:
        module_print("[pattern-analyst]",FILE_NAME, ":", *args)

def counter(packet=None):
    global count
#  packets_array.append(packet[0])
    count = count + 1

class buffer_item:
    def __init__(self, port, side = CLIENT):
        self.port = port
        self.state = 0
        self.SYN = None
        self.SYNACK = None
        self.ACK = None
        self.side = side

class summary_record:
    def __init__(self, data , str1= "", acked_pkt = None, ip=None):
        self.data = data
        self.string = str1
        self.ack = acked_pkt
        self.aggregate_set = None # will contain the fragmented packets with which the effective_len is aggregated
        self.effective_len = int(self.data.tcp.len) # aggregation of lengths of all consecutive packets
        if ip==None:
            pattern_print("WARNING: the ip is not provided, the summaries will be wrong!")
        self.cnc_ip=ip # the local IP of the machine used for traffic geenration/collection

    def summarize_pkt(self):
        summary = ""
        if self.data.ip.src==self.cnc_ip:
            summary = Server_str
        else:
            summary = Client_str
        if self.effective_len!=0:
            summary = summary + Concat_char + str(self.effective_len)
        else:
            if self.data.tcp.flags_fin=="1":
                summary = summary + Concat_char + "FIN"
            if self.data.tcp.flags_reset=="1":
                summary = summary + Concat_char + "RST"
            if self.data.tcp.flags_syn=="1":
                summary = summary + Concat_char + "SYN"
            if self.data.tcp.flags_ack=="1":
                summary = summary + Concat_char + "ACK"
        self.string = summary
        return self.string

class flow_summary:
    def __init__(self, flow_packets, cnc_ip, fsum = None, selected_filters=None):
        self.packets = flow_packets
        self.cnc_ip = cnc_ip
        self.transformations = []
        self.selected_filters = selected_filters
        if fsum==None:
            self.fsum = self.summarize_stream()
        else:
            self.fsum = fsum

    def summarize_stream(self): #creates a summary record for each packet, and groups the ACKed pairs
        summaries = []
        acked_pkts = {} # maps ack_num + len to the summary
        head = summary_record(self.packets[0], "H", self.packets[2], cnc_ip)
        summaries.append(head)
        for pkt in self.packets[3:]:
            if pkt.tcp.len=="0" and pkt.tcp.flags_ack=='1': # acknowledging a previously recieved packet
                if pkt.tcp.ack in acked_pkts:
                    if not acked_pkts[pkt.tcp.ack].ack:
                        acked_pkts[pkt.tcp.ack].ack = pkt
                    #else the packet was already acked
                else:
                    if pkt.tcp.flags=='0x00000010':
                        pattern_print(acked_pkts, "Error, the ack number", pkt.tcp.ack, "has not been seen before!")
            if not pkt.tcp.flags=='0x00000010': # it's something rather than a sole ack
                summary = summary_record(pkt, ip=self.cnc_ip)
                # summary_string = summary.summarize_pkt()
                summaries.append(summary)
                ack_num = int(pkt.tcp.seq) + int(pkt.tcp.len)
                if pkt.tcp.len=="0":
                    ack_num = ack_num + 1
                    # if pkt.tcp.flags_ack=="1" and pkt.tcp.ack_raw in acked_pkts:
                    #     acked_pkts[pkt.tcp.ack_raw].ack = pkt
                acked_pkts[str(ack_num)] = summary
        # print(acked_pkts)
        return summaries

    def apply_ACK_filter(self, summaries=None): # removes the packets that were not acked by the other point, the ACK search happens in summarize_stream
        filtered_summaries = []
        if summaries==None:
            summaries = self.fsum
        for summary in summaries:
            if summary.ack or summary.data.tcp.flags_reset=="1": #RST doesn't need ACK
                filtered_summaries.append(summary)
        # self.transformations.append(filtered_summaries)
        return filtered_summaries

    def apply_2sides_filter(self, summaries=None):
        filtered_summaries = []
        side1 = False
        side2 = False
        if summaries==None:
            summaries = self.fsum
        for summary in summaries:
            if summary.data.ip.src == summary.cnc_ip:
                side2 = True
            else:
                side1 = True
        if side1 and side2:
            filtered_summaries = summaries
        # print(filtered_summaries)
        return filtered_summaries

    def apply_aggregation(self, summaries=None): # aggregates the data length of consecutive packets to address network fragmentation
        global Concat_char
        filtered_summaries = []
        last_endpoint = ""
        if summaries==None:
            summaries = self.fsum
        for summary in summaries:
            if summary.effective_len==0: # we don't want to aggregate with control flags
                last_endpoint = "" # stop the aggregation if there was any
                filtered_summaries.append(summary)
            elif last_endpoint != summary.data.ip.src:
                last_endpoint = summary.data.ip.src
                summary.effective_len = int(summary.data.tcp.len) # TODO: can be removed
                filtered_summaries.append(summary)
            else: # the endpoint is the same and it's just different lengths stacking
                filtered_summaries[-1].effective_len += int(summary.data.tcp.len)
                if filtered_summaries[-1].aggregate_set==None:
                    filtered_summaries[-1].aggregate_set = [summary]
                else:
                    filtered_summaries[-1].aggregate_set.append(summary)
        # self.transformations.append(filtered_summaries)
        return filtered_summaries

    def apply_filters(self, summaries=None):
        if summaries==None:
            summaries = self.fsum
        # self.transformations.append(self.fsum) # it's just a reference copy, modifications on the fields will be reflected in all copies
        if self.selected_filters and self.selected_filters[0]:
            filtered_summaries = [summaries[0]] # Handshake is a special case
            filtered_summaries += self.apply_ACK_filter(summaries[1:])
            self.fsum = filtered_summaries
            # self.transformations.append(filtered_summaries)
        self.fsum = self.apply_2sides_filter()
        if self.selected_filters and self.selected_filters[1]:       
            self.fsum = self.apply_aggregation()
            # self.transformations.append(self.fsum)
        return self.fsum

    def print_summary(self, summaries=None):
        if summaries==None:
            summaries = self.fsum
        ret_str = ""
        for summary in summaries:
            if ret_str!="":
                summary.summarize_pkt()
                ret_str = ret_str + MSG_SEP + summary.string
            else:
                if summary.string == "H":
                    ret_str = ret_str + summary.string
                else:
                    pattern_print("ERROR; the handshake record is not within summaries")
                    return ""
        return ret_str
    
    def transform(self):
        self.apply_filters()
        return self.print_summary()

# using globals since inspect packet function doesn't have any arguments

port_dict = {} # the series of packets indexed based on the ports
FILE_NAME = ""

cnc_ip = None

id = 0
count = 0

buffer = [] # the buffer holding the handshake packets

def build_LCS_table(first_msgs, second_msgs):
    global MSG_SEP
    len_p1 = len(first_msgs)
    len_p2 = len(second_msgs)
    lcs_table = []
    # lcs_table = [[0]*(len_p2+1)]*(len_p1+1)
    for i in range(len_p1+1):
        lcs_table.extend([[0]*(len_p2+1)])
    for i in range(1,len_p1+1):
        for j in range(1,len_p2+1):
            if first_msgs[i-1] == second_msgs[j-1]:
                lcs_table[i][j] = lcs_table[i-1][j-1] + 1
            else:
                # print(i,j)
                lcs_table[i][j] = max(lcs_table[i][j-1], lcs_table[i-1][j])
    return lcs_table

def backtrack_LCS(lcs_table, pattern1, pattern2, s_i, s_j):
    if s_i == 0 or s_j==0:
        return ""
    if pattern1[s_i-1]==pattern2[s_j-1]:
        rest = backtrack_LCS(lcs_table, pattern1, pattern2, s_i-1, s_j-1)
        if rest:
            rest = rest + MSG_SEP
        rest = rest + pattern1[s_i-1]
        return rest
    if lcs_table[s_i][s_j-1]>lcs_table[s_i-1][s_j]:
        return backtrack_LCS(lcs_table, pattern1, pattern2, s_i, s_j-1)
    return backtrack_LCS(lcs_table, pattern1, pattern2, s_i-1, s_j)

def find_LCS(summarized_flow1, summarized_flow2):
    global MSG_SEP
    first_msgs = summarized_flow1.split(MSG_SEP)
    second_msgs = summarized_flow2.split(MSG_SEP)
    lcs_table = build_LCS_table(first_msgs, second_msgs)
    return backtrack_LCS(lcs_table, first_msgs, second_msgs, len(first_msgs), len(second_msgs))

def analyze_packet(pkt):
    counter(pkt)
    global buffer, port_dict, cnc_ip, id, PRINT
    src_port = 0 # src_port always points to the VM machine port
    side = 0 # side shows which side (VM or the CnC) initiated the communication
    # the CnC addr should be used to detect the needed traffic
    if 'tcp' in dir(pkt):
        if cnc_ip:
            if pkt.ip.dst==cnc_ip:
                src_port = pkt.tcp.srcport
                side = CLIENT
            elif pkt.ip.src==cnc_ip:
                src_port = pkt.tcp.dstport
                side = SERVER
            else:
                return
        else:
            pattern_print("Error, CnC IP was not provided!")
            return
        in_buffer = None
        if src_port and (src_port in port_dict): # connection is already established
            if pkt.tcp.len!='0' and port_dict[src_port][-1].tcp.len!='0' and port_dict[src_port][-1].tcp.seq==pkt.tcp.seq:
                pattern_print("Data Retransmission!")
            else:
                port_dict[src_port].append(pkt)
            in_buffer = True
        elif len(buffer)>0:
            remove_item = -1
            in_buffer = False
            for i in range(0,len(buffer)):
                item = buffer[i]
                if item.port==src_port:
                    in_buffer = True
                    if item.side==side:
                        if item.state==2: # Possibly state change
                            if pkt.tcp.flags=="0x00000010": # Only the ACK should be set
                                item.state=3
                                item.ACK=pkt
                                if item.port in port_dict:
                                    pattern_print("port", item.port,"has been used before; appending the new ones to them!")
                                    port_dict.extend([item.SYN, item.SYNACK, item.ACK])
                                else:
                                    port_dict[item.port] = [item.SYN, item.SYNACK, item.ACK]
                                remove_item = i
                            else:
                                pattern_print("Error in the TCP handshake, expected ACK!")
                        elif item.state==1: 
                            if pkt.tcp.flags=='0x00000002':# retransmission possibly due to network errors
                                pattern_print("Retransmission!")
                                item.SYN = pkt
                            else:
                                pattern_print("Error in the TCP handshake, expected SYN-ACK!")
                        # state 3 is established so no need to check it                          
                    elif item.state==1:
                        if pkt.tcp.flags == '0x00000012': # only ACK and SYN should be set
                            item.state=2
                            item.SYNACK=pkt
                        else:
                            pattern_print("Error in the TCP handshake, expected SYN-ACK!") # usually it's the other end sending RST
                    elif item.state==2:
                        if pkt.tcp.flags == '0x00000012': # retransmission possibly due to network errors
                            item.SYNACK=pkt
                        else:
                            pattern_print("Error in the TCP handshake, expected ACK!") 
                    else:
                        pattern_print("Error in the TCP handshake. didn't expect this state!")
            if remove_item>=0:
                del buffer[remove_item]
        if not in_buffer:
            if pkt.tcp.flags=='0x00000002': # Only SYN should be set
                if len(buffer)>=BUFFER_SIZE:
                    pattern_print("Warning, buffer has reached its limit!")
                    buffer.pop(0)
                new_item = buffer_item(src_port,side)
                new_item.state = 1
                new_item.SYN = pkt
                buffer.append(new_item)
            else:
                pattern_print("malformed communication, packet before a complete handshake!")

    # print(pkt)

def extract_flows(pcap, ip=None, print_status=False):
    global FILE_NAME, PRINT, port_dict, count, cnc_ip
    PRINT = print_status
    port_dict.clear()
    count = 0
    cnc_ip = ip
    ports_added = []
    if not os.path.isfile(pcap):
        PRINT = True # serious error; must be always reported
        pattern_print("Input is not a file ",str(pcap))
        pattern_print("Exiting now")
        exit(1)
    else:
        if len(pcap)>100:
            FILE_NAME = pcap[100:]
        else:
            FILE_NAME = pcap
    cap = pyshark.FileCapture(pcap)
    pattern_print("****Serializing ports****")

    cap.apply_on_packets(analyze_packet)

    pattern_print("***********")
    return port_dict

def summarize_flows(flows, cnc_ip, selected_filters = None):
    summaries = {}
    for src_port in flows:
        summary = flow_summary(flows[src_port], cnc_ip, fsum=None, selected_filters=selected_filters)
        summaries[src_port] = summary
    return summaries
# This function should be replaced with another one that calls this with the flow summaries instead of
# passing the raw packets; the reason is the possibility of getting the results with multiple filters
def extract_transformations(flows): # get the filters setting
    all_patterns = {}
    summaries = []
    for src_port in flows:
        summary = flows[src_port] # pass the filters
        printable_summary = summary.transform()
        if printable_summary in all_patterns:
            all_patterns[printable_summary] +=1
        else:
            all_patterns[printable_summary] = 1
            pattern_print(src_port, printable_summary)
        summaries.append(summary)
    return all_patterns

def verify_both_ends(str1):
    client_data = Client_str + "_\d"
    server_data = Server_str + "_\d"
    v1 = re.findall(client_data, str1)
    v2 = re.findall(server_data, str1)
    if len(v1)>0 and len(v2)>0:
        return True
    else:
        return False

def extract_pattern(t_strings):
    global Server_str, Client_str
    patterns = {}
    if len(t_strings)==0:
        return patterns
    list_t = list(t_strings.keys())
    len_l = len(list_t)

    for i in range(len_l):
        if t_strings[list_t[i]]>1:
            if list_t[i] in patterns:
                patterns[list_t[i]] += t_strings[list_t[i]]
            else:
                patterns[list_t[i]] = t_strings[list_t[i]]
        j = i + 1
        while j<len_l:
            lcs = find_LCS(list_t[i], list_t[j])
            if verify_both_ends(lcs):  # verify that both endpoints exchanged data
                if lcs in patterns:
                    patterns[lcs] +=1
                else:
                    patterns[lcs] = 1
            j += 1
    return patterns
def transform_and_extract(s_flows):
    for p in s_flows:
        s_flows[p].selected_filters = [True, False]
    t_strings = extract_transformations(s_flows)
    patterns = extract_pattern(t_strings)
    if len(patterns)==0:
        pattern_print("After aggregation")
        for p in s_flows:
            s_flows[p].selected_filters = [False, True]
        t_strings = extract_transformations(s_flows)
        patterns = extract_pattern(t_strings)
    else:
        pattern_print("Without aggregation")
    return patterns

def find_pattern(pcap_file, cnc_ip):
    flows = extract_flows(pcap_file, ip=cnc_ip, print_status=False)
    s_flows = summarize_flows(flows, cnc_ip)
    return transform_and_extract(s_flows)

def just_transform(pcap_file, cnc_ip):
    flows = extract_flows(pcap_file, ip=cnc_ip, print_status=False)
    s_flows = summarize_flows(flows, cnc_ip)
    return extract_transformations(s_flows)

# this function checks whether any pattern from the first set have an intersection with the any pattern from the second set
# one basic use could be checking whether two sessions (generating multiple flows) have any similarity
def do_patterns_intersect(patterns1, patterns2):
    for ptr1 in patterns1:
        for ptr2 in patterns2:
            lcs = find_LCS(ptr1, ptr2)
            if verify_both_ends(lcs):  # verify that both endpoints exchanged data
                return lcs
    return None

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-pcap", type=str, help="the pcap file", required=True)
    parser.add_argument("-cncIP", type=str, help="the CnC IP", required=True)
    parser.add_argument("-csvfile", type=str, help="the CnC IP", default=PATTERN_FILE)
    parser.add_argument("-store", required=False, default=False, action='store_true', help="Store output to a CSV DB")
    parser.add_argument("-transform", required=False, default=False, action='store_true', help="Only transform the flows to a string in our grammer")
    args = parser.parse_args()
    to_output = ""
    ip = args.cncIP.split(":")[0] # the input should be the complete address, because it's used as the table key
    if args.transform:
        to_output = just_transform(args.pcap, ip)
    else:
        to_output = find_pattern(args.pcap, ip)
    if args.store:
        fields = ["Hash", "iteration", "src_port", "cnc_addr", "pattern"]
        fnames = args.pcap.split(os.sep)
        if len(fnames)>=4:
            Hash_name = fnames[-4]
            iteration = fnames[-3]
            dict_rec = {"Hash":Hash_name, "iteration":iteration, "cnc_addr":args.cncIP, "pattern":to_output}
            write_to_csv(dict_rec,args.csvfile,fields)
        else:
            print("the pcap path is not in the expected format; can't write to the CSV DB")
    else:
        print(to_output)
