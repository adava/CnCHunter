import fcntl
import sys
import csv
import os
import ipaddress
from datetime import datetime
if __package__==None or __name__=="util":
    from config_params import *
else:
    from .config_params import *

MODULE_NAME = ""
MALWARE_INSTANCE = ""

csvW = {}
def module_print(*args):
    fcntl.flock(sys.stdout, fcntl.LOCK_EX)
    print(*args)
    fcntl.flock(sys.stdout, fcntl.LOCK_UN)


def get_subnet(ip, sub_mask=None):
    global DEFAULT_MASK
    if not sub_mask:
        sub_mask = DEFAULT_MASK
    try:
        ip = ipaddress.IPv4Address(ip)
    except:
        return None # not resolved DNS addresses could lead to this path
    subnet_int = int(ip) & sub_mask
    subnet = str(ipaddress.IPv4Address(subnet_int))
    return subnet

def get_date(date_str):
    if not date_str:
        return None
    parts = date_str.split("_")
    date1 = parts[0].split("-")
    if len(date1)!=3 or len(parts)!=2:
        print("timestamp format is wrong, expected MM-DD-YYYY_HH:MM:SS but this was given:", date_str)
        return None
    else:
        month = int(date1[0])
        day = int(date1[1])
        year = int(date1[2])
    time1=parts[1].split(":")
    if len(time1)!=3:
        print("timestamp format is wrong, expected MM-DD-YYYY_HH:MM:SS but this was given:", date_str)
        return None
    else:
        hour = int(time1[0])
        min = int(time1[1])
        sec = int(time1[2])
    date_time = datetime(year,month,day,hour,min,sec)
    return date_time

def write_to_csv(dictd, filename=CNCS_FILE, fields=None):
    global csvW, cncFields
    if fields==None:
        fields = cncFields
    write_header = False
    if not os.path.isfile(filename):
        write_header = True
    if filename not in csvW or "file" not in csvW[filename]: # no race, they are accessed in different processes
        csvW[filename] = {}
        csvW[filename]["file"] = open(filename,"a")
    if "writer" not in csvW[filename]:
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

def read_from_csv(filename=CNCS_FILE,always_refresh=False):
    global csvW
    if not os.path.isfile(filename):
        print(filename, "does not exist!")
        return None
    if filename not in csvW or always_refresh: # no race, they are accessed in different processes
        csvW[filename] = {}
        csvW[filename]["file_r"] = open(filename,"r")
    if "reader" not in csvW[filename]:
        csvW[filename]["reader"] = csv.DictReader(csvW[filename]["file_r"])
    return csvW[filename]["reader"]

# the CSVDic should be read into this dictionary because it can be read only once
# plus, search using the dic key is faster
def read_into_dic(patterns, field ="cnc_addr"):
    pat_bk = {}
    for record in patterns:
        if field in record:
            pat_bk[record[field]] = record
    return pat_bk

def check_last_line(filename):
    last_line = None
    with open(filename, 'rb') as f:
        try:  # catch OSError in case of a one line file 
            f.seek(-2, os.SEEK_END)
            while f.read(1) != b'\n':
                f.seek(-2, os.SEEK_CUR)
        except OSError:
            f.seek(0)
        last_line = f.readline().decode()
    return last_line
