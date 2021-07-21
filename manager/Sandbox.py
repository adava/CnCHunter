import os
import sys
from profiler.StaticAnalysis import *
# from profiler.DynamicAnalysis import *
from profiler.traffic_analyst import *
import time
import random
import sqlite3
from sqlite3 import Error
import collections

import logging

from datetime import datetime

import traceback

l = logging.getLogger(name=__name__)

RESULT_DIR = "/analysis/result/"
FILESYSTEM_DIR = "/filesystem/"
DIR_SCRIPTS = "/scripts/"
RARE_DYNAMIC_COMMAND = DIR_SCRIPTS + "rare_dynamic.sh"
STOP_RARE_COMMAND = DIR_SCRIPTS + "stop_rare.sh"
MOUNTING_HANDLER = DIR_SCRIPTS + "mounting_handler.sh"
PREPARE_FS = DIR_SCRIPTS + "preparefs.sh"
GETDATA_FROM_FS_COMMAND = DIR_SCRIPTS + "getdatafromFS.sh"
GET_IP_FROM_PCAP = DIR_SCRIPTS + "get_ip_from_pcap.sh"
START_NET_COMMAND = DIR_SCRIPTS + "start_network.sh"
STOP_NET_COMMAND = DIR_SCRIPTS + "stop_network.sh"
DEFAULT_MAC_FILE_NAME = "/mac_addr"


class InitSandbox:
    def __init__(self, abs_path, iteration, name, experiment_time, prev_runs_result, CnC_addr=None, CnC_target = None, excluded_ports = None, Alexa_ranking=-1):
        """
        :param abs_path:
        :param iteration:
        :param name:
        :param experiment_time:
        :param prev_runs_result: object ResultObject
        """
        l.warning("Initializing Sandbox for: iteration(%d) %s (%d sec)", iteration, name, experiment_time)
        self.abs_path = abs_path
        self.iteration = iteration
        self.name = name
        self.experiment_time = experiment_time - 20
        self.prev_runs_result = prev_runs_result

        self.CnC_addr = CnC_addr
        self.Destination_CnC_Addr = CnC_target
        self.excluded_ports = excluded_ports
        self.Alexa_ranking = Alexa_ranking

        self.arch = "mips" #should be modified based on my function result (see the run script)
        self.temporary_folder = "FAIL"
        self.built_fs = False
        # self._static_analysis() TODO: move the arch analysis and the rest here?
        self.use_debian = False # Do not change this
        self.file_system = self._create_fs()
        self.result_directory = self._make_result_dir()
        self.pcap_directory = self._make_pcap_dir()
        self.pcap_file = self.pcap_directory + "/qemu_wan.pcap"

        # TODO: add support for interComm
        self.connection = {}
        self.ip_addr = ""
        self.mac_addr = ""
        self.start_time = 0

        # iterative learner

    def start(self):
        if self.use_debian:
            print("Using Debian host is not currently supported, exiting...")
            sys.exit()
        self._random_MAC()        
        try:
            params = [self.abs_path + RARE_DYNAMIC_COMMAND,
                                        self.abs_path,
                                        self.pcap_directory,
                                        self.file_system, str(self.use_debian), self.mac_addr]
            if self.iteration>=1:
                proc = subprocess.Popen(self.abs_path + STOP_NET_COMMAND, stdout=subprocess.PIPE)
                out1, err1 = proc.communicate()
                if err1:
                    l.error("Couldn't stop network for %s iteration: %s", self.iteration, err)
                proc = subprocess.Popen(self.abs_path + START_NET_COMMAND, stdout=subprocess.PIPE)
                out2, err2 = proc.communicate()
                if err2:
                    l.error("Couldn't start network for %s iteration: %s", self.iteration, err)
            proc = subprocess.Popen(params, stdout=subprocess.PIPE)
            out, err = proc.communicate()
            self.start_time = time.time()
            if err:
                l.error("error occurred before starting qemu: %s", err)
            else:
                l.warning("%d_%s: started sandbox on mac: %s", self.iteration, self.name, self.mac_addr)
        except Exception as err:
            print(err)

    def stop_and_get_data_out(self):
        try:
            proc = subprocess.Popen([self.abs_path + STOP_RARE_COMMAND, self.name], stdout=subprocess.PIPE)
            out, err = proc.communicate()
            if err:
                l.error("can't stop sandbox %d_%s", self.iteration, self.name)
            else:
                l.warning("%d_%s: stopped sandbox", self.iteration, self.name)
        except Exception as err:
            print(err)
        try:
            proc = subprocess.Popen([self.abs_path + GETDATA_FROM_FS_COMMAND, self.abs_path, self.name,
                                        self.temporary_folder, "NO"], stdout=subprocess.PIPE)
            proc.communicate()
            l.warning("data out %d_%s", self.iteration, self.name)
            l.warning("done with iteration(%d) %s", self.iteration, self.name)
            l.warning("-" * 50)
        except Exception as err:
            print(err)

    def get_data_out(self):
        try:
            proc = subprocess.Popen([self.abs_path + GETDATA_FROM_FS_COMMAND, self.abs_path, self.name,
                                        self.temporary_folder, "NO"], stdout=subprocess.PIPE)
            proc.communicate()
            l.warning("data out %d_%s", self.iteration, self.name)
            l.warning("done with iteration(%d) %s", self.iteration, self.name)
            l.warning("-" * 50)
        except:
            self.get_data_out()

    def generate_analysis_result(self):
        syscall_trace = self.result_directory + "/syscalls/" + self.name + ".log"
        pcap_file = self.result_directory + "/pcap/" + "qemu_wan" + ".pcap"        
        if not os.path.isfile(pcap_file):
            l.warning(" pcap file %s does not exist", pcap_file)
            return None
        if not os.path.isfile(syscall_trace):
            l.warning(" system call trace file %s does not exist", syscall_trace)
            return None
        l.warning("%d_%s: generating analysis result ", self.iteration, self.name)
        ret_res = (find_cnc(pcap_file, self.ip_addr, self.excluded_ports, True, self.Alexa_ranking),)
        l.warning("%d_%s: analysis result ready", self.iteration, self.name)
        return ret_res

    def _random_MAC(self):
        _mac = [random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff)]
        self.mac_addr = "52:54:00:" + ':'.join(map(lambda x: "%02x" % x, _mac))

    def _assign_mac_addr(self):
        try:
            with open(self.pcap_directory + DEFAULT_MAC_FILE_NAME, "r") as mac_file:
                for line in mac_file:
                    self.mac_addr = line[:-1]
                    break
        except:
            time.sleep(3)
            self._assign_mac_addr()

    def _get_ip_from_pcap(self):
        # print("abs_path=",self.abs_path, "script=", GET_IP_FROM_PCAP, "pcap_file=", self.pcap_file)
        l.warning("%d_%s: getting ip of the instance", self.iteration, self.name)
        try:
            proc = subprocess.Popen([self.abs_path + GET_IP_FROM_PCAP, self.pcap_file], stdout=subprocess.PIPE)
            out, err = proc.communicate()
            if err:
                l.error("%d_%s: error getting ip", self.iteration, self.name)
            else:
                out = out.decode("utf-8")
            if "False" not in out:
                self.ip_addr = out.split()[-1]
        except Exception as e:
            print("Exception in executing get_ip script: " + str(e))
            # traceback.print_stack()
            pass

    def _create_fs(self):
        l.warning("%d_%s: creating filesystem", self.iteration, self.name)
        target_ip = None
        target_port = None
        cnc_addr = None
        if self.CnC_addr:
            if validate_ip_format(self.CnC_addr):
                li = self.CnC_addr.split(":")
                if len(li)==2:
                    target_ip = li[0]
                    target_port = li[1]
                    cnc_addr = self.Destination_CnC_Addr
                else:
                    l.warning("[%d_%s creating filesystem] the cnc_addr does not have the port num: %s", self.iteration, self.name, self.CnC_addr)
            else:
                target_ip = self.CnC_addr
                target_port = "any"
                cnc_addr = self.Destination_CnC_Addr

        self._mounting_handler()
        try:
            params = []
            if target_ip and target_port and cnc_addr:
                params = [self.abs_path + PREPARE_FS, self.name, str(self.iteration), self.abs_path,
                                        str(self.experiment_time), "NO", "NO",
                                        self.temporary_folder, target_ip, target_port, cnc_addr]
            else:
                if self.iteration>0:
                    l.warning("[%d_%s creating filesystem] not in redirection mode!", self.iteration, self.name)
                params = [self.abs_path + PREPARE_FS, self.name, str(self.iteration), self.abs_path,
                    str(self.experiment_time), "NO", "NO",
                    self.temporary_folder]
            proc = subprocess.Popen(params,
                                    stdout=subprocess.PIPE)
            out, err = proc.communicate()
            if err:
                print(err)
                print("creating filesystem for",self.name[:10],"iteration",self.iteration,"failed")
                sys.exit()
            else:
                l.warning("%d_%s: done creating filesystem", self.iteration, self.name)
                self.built_fs = True
            return self.abs_path + FILESYSTEM_DIR + self.name + ".ext4"
        except Exception as err:
                print(err)
                time.sleep(10)
                self._create_fs()

    def _mounting_handler(self):
        while self.temporary_folder == "FAIL":
            try:
                proc = subprocess.Popen([self.abs_path + MOUNTING_HANDLER,
                                         self.name,
                                         self.abs_path], stdout=subprocess.PIPE)
                out, err = proc.communicate()
                self.temporary_folder = out.split()[-1]
            except:
                pass
            time.sleep(5)


    def _static_analysis(self):
        l.warning("collecting static analysis information %s", self.name)
        static_analysis_result = Static(self.abs_path, self.name, "")

    def _make_result_dir(self):
        result_dir = self.abs_path + RESULT_DIR + self.name + "/" + str(self.iteration)
        if not os.path.isdir(result_dir):
            os.makedirs(result_dir)
        else: # Get a backup of the former results
            current_time = datetime.now().strftime("%m-%d-%Y-%H_%M_%S")
            new_name = result_dir + "_" + current_time +".bk"
            os.rename(result_dir,new_name)
            os.makedirs(result_dir)
        return result_dir

    def _make_pcap_dir(self):
        pcap_dir = self.result_directory + "/pcap"
        if not os.path.isdir(pcap_dir):
            os.makedirs(pcap_dir)
        return pcap_dir


