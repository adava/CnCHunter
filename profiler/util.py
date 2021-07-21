import fcntl
import sys
import csv
import os

MODULE_NAME = ""
MALWARE_INSTANCE = ""

cncFields = ["sample_name", "CnC_Addr", "RST", "SYN", "DNS_Name", "live_comm", "misc"]

csvW = {}
def module_print(*args):
    fcntl.flock(sys.stdout, fcntl.LOCK_EX)
    print(*args)
    fcntl.flock(sys.stdout, fcntl.LOCK_UN)

def write_to_csv(dictd, filename="cncs.csv", fields=None):
    global csvW, cncFields
    if fields==None:
        fields = cncFields
    if filename not in csvW: # no race, they are accessed in different processes
        write_header = False
        if not os.path.isfile(filename):
            write_header = True
        csvW[filename] = {}
        csvW[filename]["file"] = open(filename,"a")
        csvW[filename]["writer"] = csv.DictWriter(csvW[filename]["file"], delimiter=",",fieldnames=fields, quoting=csv.QUOTE_MINIMAL)
        if write_header:
            csvW[filename]["writer"].writeheader()
    towrite = {}
    for key in fields:
        if key not in dictd:
            towrite[key] = "" #value would not be serialized
        else:
            towrite[key] = dictd[key]
    
    fcntl.flock(csvW[filename]["file"], fcntl.LOCK_EX)
    csvW[filename]["writer"].writerow(towrite)
    fcntl.flock(csvW[filename]["file"], fcntl.LOCK_UN)
    
    csvW[filename]["file"].flush()


def prepare_row(ip, dict_vals, dict_mapping, ip_key="CnC_Addr"):
    dic = {ip_key:ip}
    for key in dict_vals:
        if key in dict_mapping:
            dic[dict_mapping[key]] = dict_vals[key]
        else:
            dic[key] = dict_vals[key]
    return dic