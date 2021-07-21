#!/usr/bin/python

import signal
import logging
import sys
import os
import subprocess
import time
import threading
from manager.Manager import *
from datetime import datetime

from elftools.elf.elffile import ELFFile
from multiprocessing import Process #threading and pyshark wouldn't go well
import argparse

now = datetime.now()
current_time = now.strftime("%m-%d-%Y-%H_%M_%S")
logging.basicConfig(filename='riotman_' + current_time + '.log', filemode='w', format='%(asctime)s-%(levelname)s-%(message)s',
                    datefmt='%d-%b-%y %H:%M:%S')
BANNER = """
 ██████╗███╗   ██╗ ██████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝████╗  ██║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║     ██╔██╗ ██║██║         ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║     ██║╚██╗██║██║         ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╗██║ ╚████║╚██████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝╚═╝  ╚═══╝ ╚═════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                                                                            
"""

PARALLEL_INSTANCES = 1 # Don't increase this TODO: need to resolve DHCP problem with more parallel instances
EXPERIMENT_TIME = 140
POLLING_WAIT = [EXPERIMENT_TIME, EXPERIMENT_TIME / 2, EXPERIMENT_TIME / 4]
LIST_NEED_DEBIAN = []
LIST_FAILED = []
LIST_0_FAILED = []
LIST_FORCE_STOPPED = []
ALL_DONE = False
ULTIMATE_TIMER = 1000

CUR_DIR = os.path.dirname(os.path.realpath(__file__))
DIR_SCRIPTS = CUR_DIR + os.sep + "scripts" + os.sep
STOP_RARE_COMMAND = DIR_SCRIPTS + "stop_rare.sh"
start_network_command = DIR_SCRIPTS + "start_network.sh"
stop_network_command = DIR_SCRIPTS + "stop_network.sh" 

set_running_instances = set()

supported_architectures = {"MIPS":{32:["B"]}}
def is_platform_supported(filename, supported_architectures):
    try:
        fi = open(filename,"rb")
        elffile = ELFFile(fi)
        arch = elffile.get_machine_arch()
        if arch in supported_architectures:
            if elffile.elfclass in supported_architectures[arch]:
                Endianness = ""
                if elffile.little_endian:
                    Endianness = "L"
                else:
                    Endianness = "B"
                if Endianness in supported_architectures[arch][elffile.elfclass]:
                    return True
                else:
                    l.warning("File %s Endianness %s is not supported", filename, Endianness)
                    return False
            else:
                l.warning("File %s address size %d is not supported", filename, elffile.elfclass)
                return False
        else:
            l.warning("File %s architecture %s is not supported", filename, arch)
            return False
    except:
        l.error("Coudln't parse file %s (supposed to be elf)",filename)
        return False

def find_malware(dir_name):
    list_malware = []
    for dirname, dirnames, filenames in os.walk(dir_name):
        for subdirname in filenames:
            list_malware.append(subdirname)
    return list_malware


def force_kill_malware(sandbox_instance):
    proc = subprocess.Popen([STOP_RARE_COMMAND, sandbox_instance.name], stdout=subprocess.PIPE)
    out, err = proc.communicate()
    if err:
        l.error("FORCE: can't stop sandbox %d_%s", sandbox_instance.iteration, sandbox_instance.name)
    else:
        l.warning("FORCE: %d_%s: stopped sandbox", sandbox_instance.iteration, sandbox_instance.name)
    sandbox_instance.get_data_forcefully()
    LIST_FORCE_STOPPED.append(str(sandbox_instance.iteration) + "," + sandbox_instance.name)


def release_done_instances(set_running_instances):
    global ULTIMATE_TIMER
    result = set()
    for p, instance in set_running_instances:
        ts = time.time()
        if not instance.done_experiments and p.is_alive():
            if (ts - instance.analysis_time_overall) < ULTIMATE_TIMER + sum(instance.fs_slowness):
                result.add((p,instance))
            else:
                l.warning("Ultimatae_Timer: %d surpassed.", ULTIMATE_TIMER)
                force_kill_malware(instance)
                p.terminate()
        else:
            if instance.failed and instance.iteration == 0:
                LIST_0_FAILED.append(str(instance.iteration) + "," + instance.name)
            elif instance.failed:
                LIST_FAILED.append(str(instance.iteration) + "," + instance.name)
    return result

def stop_all_instances(set_instances):
    for p, instance in set_instances:
        if not p.is_alive():
            force_kill_malware(instance)
            p.terminate()


def main(CnC_addresses=None):
    global ALL_DONE, ULTIMATE_TIMER
    global supported_architectures, set_running_instances, start_network_command, stop_network_command, CUR_DIR
    list_malware_name = find_malware("malware/malware")
    proc = subprocess.Popen(start_network_command, stdout=subprocess.PIPE)
    out, err = proc.communicate()


    index_malware, number_of_malware = 0, len(list_malware_name)

    len_attacks = 1
    if CnC_addresses and 'IPs' in CnC_addresses:
        len_attacks +=len(CnC_addresses['IPs'])
    ULTIMATE_TIMER = ULTIMATE_TIMER + number_of_malware * EXPERIMENT_TIME * len_attacks + (PARALLEL_INSTANCES*EXPERIMENT_TIME)

    polling_wait_index = 0
    while index_malware < number_of_malware:
        if len(set_running_instances) < PARALLEL_INSTANCES:
            if(is_platform_supported(os.path.join(os.path.join(CUR_DIR,"malware/malware"), list_malware_name[index_malware]),supported_architectures)):
                new_instance = None
                if CnC_addresses:
                    new_instance = Controller(EXPERIMENT_TIME, CUR_DIR, list_malware_name[index_malware], CnC_addresses)
                else:
                    new_instance = Controller(EXPERIMENT_TIME, CUR_DIR, list_malware_name[index_malware])
                # mainloop_thread = threading.Thread(target=new_instance.analyze_and_MitM)
                # mainloop_thread.daemon = True
                # mainloop_thread.start()
                print("[Master] instantiating the controller for ",list_malware_name[index_malware])
                p = Process(target=new_instance.analyze_and_MitM, args=())  #threading and pyshark wouldn't go well
                p.start()
                set_running_instances.add((p,new_instance))
                #p.join()
                index_malware += 1
            else:
                index_malware += 1
        else:
            print("[Master] Waiting %d seconds for the parallel instances to finish" % POLLING_WAIT[polling_wait_index % len(POLLING_WAIT)])
            time.sleep(POLLING_WAIT[polling_wait_index % len(POLLING_WAIT)])
            set_running_instances = release_done_instances(set_running_instances)
            polling_wait_index += 1
    while len(set_running_instances) != 0:
        time.sleep(POLLING_WAIT[polling_wait_index % len(POLLING_WAIT)])
        set_running_instances = release_done_instances(set_running_instances)
        polling_wait_index += 1

    proc = subprocess.Popen(stop_network_command, stdout=subprocess.PIPE)
    out, err = proc.communicate()
    ALL_DONE = True
    sys.exit()

def clean_up():
	print("cleaning up...")
	global set_running_instances, DIR_SCRIPTS, stop_network_command
	try:
		stop_all_instances(set_running_instances)
	except:
		pass
	proc1 = subprocess.Popen(stop_network_command, stdout=subprocess.PIPE)
	out, err1 = proc1.communicate()
	proc1.wait()
	kill_all_ps = DIR_SCRIPTS + "killAll.sh"
	proc2 = subprocess.Popen(kill_all_ps)
	out, err2 = proc2.communicate()
	proc2.wait()

def recv_signal(sig_num, frame):
	print("Exiting on signal :", sig_num)
	clean_up()
	sys.exit()
if __name__ == "__main__":
    print(BANNER)
    signal.signal(signal.SIGINT, recv_signal)
    print("[Master] Press CTRL+C whenever you want to exit")  
    parser = argparse.ArgumentParser()
    parser.add_argument("-target", nargs='*', type=str, help="the target CnC Address e.g. 104.168.98.105:45 or 104.168.98.0/24:45")
    parser.add_argument("-ports", nargs='*', type=str, help="the ports to be excluded like 23 (attributed to other activities like scanning)")
    parser.add_argument("-Alexa", type=int, default=-1,help="Whether using Alexa ranking for whitelisting and what should be the cutoff")
    args = parser.parse_args()
    arguments = ()
    args_dict = {}
    if args.target:
        addr_list = generate_addr_list(args.target)
        if addr_list!=None:
            args_dict['IPs'] = addr_list
        else:
            print("[Master] Error in parsing the target arguments!")
            sys.exit()       
    else:
        print("[Master] Only finding currently contacted CnCs")
    if args.ports:
         args_dict['PORTs'] = args.ports
    args_dict["Alexa"] = args.Alexa
    if len(args_dict):
        arguments = (args_dict,)
    
    p = Process(target=main, args=arguments)  #threading and pyshark wouldn't go well
    p.start()
    p.join()
    clean_up()
    # mainloop_thread = threading.Thread(target=main)
    # mainloop_thread.daemon = True
    # mainloop_thread.start()
