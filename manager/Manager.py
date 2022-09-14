import logging

l = logging.getLogger(name=__name__)
import os, sys
from manager.Sandbox import *
# from profiler.DynamicAnalysis import *
from profiler.traffic_analyst import *
from profiler.util import *
from profiler.config_params import *
# from manager.AnalysisResult import *
from datetime import datetime
import time
import collections
import sqlite3
import __future__

# ALLOWED_MAX_ITERATION = 2
POLLING_WAIT = 10
T_LIMIT_IP = 60 * 5

INSTANCE_NAME = ""

def manager_print(*args):
    global INSTANCE_NAME
    module_print("[Manager]",INSTANCE_NAME, ":", *args)

class Controller:
    def __init__(self, experiment_time, abs_path, mal_name, options= None):
        global INSTANCE_NAME
        l.warning(" " * 40 + "Starting analysis for %s", mal_name)
        # responsibility for this module is to keep track of iterations and control everything.
        self.experiment_time = experiment_time
        self.abs_path = abs_path
        self.name = mal_name
        INSTANCE_NAME = self.name[-7:]
        self.done_experiments = False
        self.iteration = 0
        self.dic_analysis_result = {}
        self.report_dir = self.abs_path + "/report/" + self.name + "/"
        self.firmware_db = self.abs_path + "/firmware.db"
        self.needs_debian = False
        self.failed = False
        self.instance_object = None
        self.analysis_time_overall = time.time()
        self.fs_slowness = []
        self.finished_time = float("inf")
        self.missing_configs = []
        self.cnc_report = None
        if options and "IPs" in options:
            self.target_CnCs = options["IPs"]
        else:
            self.target_CnCs = None
        if self.target_CnCs:
            self.num_of_iterations = len(self.target_CnCs) + 1 #try to MitM and hunt
        else:
            self.num_of_iterations = 1 #just find the CnC
        if options and "PORTs" in options:
            self.excluded_ports = options["PORTs"]
        else:
            self.excluded_ports = None
        
        if options and "Alexa" in options:
            self.Alexa_ranking = options["Alexa"]
        else:
            self.Alexa_ranking = -1
        if options and "CnCAddr" in options:
            self.cnc_addr = options["CnCAddr"]
        else:
            self.cnc_addr = None
        self.success_CnC_connections = {}
        rep_it = self.num_of_iterations
        if self.cnc_addr:
            rep_it -= 1
        manager_print("Num of iterations: ", rep_it)

    def analyze_and_MitM(self):
        cnc_addr = self.cnc_addr
        range_start = 0
        if cnc_addr:
            range_start = 1
        i = 0
        for i in range(range_start, self.num_of_iterations):
            manager_print(": starting iteration ", i)
            iteration_target_cnc_ip = ""
            self.instance_object = None
            if cnc_addr:
                iteration_target_cnc_ip = self.target_CnCs.pop(0)
                manager_print(": profiling ", iteration_target_cnc_ip)
                self.instance_object = InitSandbox(self.abs_path, i, self.name, self.experiment_time, self.dic_analysis_result, cnc_addr, iteration_target_cnc_ip, self.excluded_ports, self.Alexa_ranking)
            elif i==0:
                self.instance_object = InitSandbox(self.abs_path, i, self.name, self.experiment_time, self.dic_analysis_result, None, None, self.excluded_ports, self.Alexa_ranking)
            else:
                manager_print("can't mount the MitM since CnC address of the sample is missing; try a longer experiment time!")
                self.done_experiments = True
                self.finished_time = time.time()
                l.warning("-" * 40 + "*" * 5 + "Done analyzing [%s, %d]" + "*" * 5 + "-" * 40, self.name, self.iteration)
                return

            # if not self.instance_object.use_debian:
            self.iteration = i
            self.instance_object.start()
            l.warning("%d_%s: Started", self.iteration, self.name)
            ts = time.time()
            self.fs_slowness.append(ts - self.analysis_time_overall)
            counter = 0
            ts = time.time()
            while (ts - self.instance_object.start_time) < T_LIMIT_IP and self.instance_object.ip_addr == "":
                time.sleep(POLLING_WAIT)
                self.instance_object._get_ip_from_pcap()
                counter += 1
                ts = time.time()
            if self.instance_object.ip_addr:
                l.warning("%d_%s: Got the IP: %s", self.iteration, self.name, self.instance_object.ip_addr)
            else:
                l.warning("%d_%s: EXCEEDED WAITING FOR IP: %d(s)", self.iteration, self.name, T_LIMIT_IP)
            time.sleep(self.experiment_time)
            # counter = 0
            # while counter < COUNTER_LIMIT and not self.instance_object.check_if_done():
            #     time.sleep(POLLING_WAIT)
            #     counter += 1
            self.instance_object.stop_and_get_data_out()
            all_result = self.instance_object.generate_analysis_result()
            if not all_result:
                l.warning("%s: Something went wrong and there was no analysis result!",self.name)
                return            
            if i==0: #the first run is for finding the CnC Addr
                self.cnc_report = all_result[-1]
                cnc_addr = self.get_CnC_addr()
                if cnc_addr:
                    and_live = ""
                    if "SUC" in self.cnc_report[0][1]:
                        and_live = "and LIVE!"
                    manager_print("CnC is Available:",cnc_addr, and_live)
                    self.serialize_cnc_info(all_result[-1],mapping={"SUC":"live_comm"})
            else:
                comms = find_success(all_result[-1],iteration_target_cnc_ip)
                info = self.prepare_info(comms, iteration_target_cnc_ip, all_result[-1])
                self.serialize_cnc_info(info,MitM_RESULT_FILE,mapping={"SUC":"responses"}, fieldnames=["sample_name", "CnC_Addr", "SYN", "responses", "misc", "timestamp"])
                        
            # TODO: we need to consider other possible CnC addresses

            self.dic_analysis_result[i] = all_result
        if len(self.success_CnC_connections)>1:
            freqs = list(self.success_CnC_connections.values())
            manager_print("Running statistics analysis on successful connections: ",str(freqs))
            outs = find_outliers(freqs, 1)
            if len(outs)>0:
                manager_print("The following are the best live CnC matches:")
                IPs = list(self.success_CnC_connections.keys())
                for i in outs:
                    manager_print(IPs[i])
                    dic = {"SYN":self.success_CnC_connections[IPs[i]]}
                    info = [(IPs[i],dic),]
                    self.serialize_cnc_info(info,"final_list.csv",fieldnames=["sample_name", "CnC_Addr", "SYN"])
        else:
            if i>1:
                manager_print("Not running statistics analysis; not enough successful connections")
        self.done_experiments = True
        self.finished_time = time.time()
        l.warning("-" * 40 + "*" * 5 + "Done analyzing [%s, %d]" + "*" * 5 + "-" * 40, self.name, self.iteration)

    def get_data_forcefully(self): #TODO: remove, does not work anymore (multiprocessing)
        if not self.done_experiments:
            l.warning("%d_%s: !!!!!!!!!!!!!!!!!! FORCE STOPPED !!!!!!!!!!!!!!!!!!", self.iteration, self.name)
            if self.instance_object: # the instance_object might not exit (before call to iterative learning)
                self.instance_object.get_data_out()
                all_result = self.instance_object.generate_analysis_result()
                if all_result:
                	self.dic_analysis_result[self.iteration] = ResultObject(self.iteration, self.name, all_result)
            else:
                self.failed = True
            self.done_experiments = True
            self.finished_time = time.time()
        else:
            l.warning("%d_%s: !!!!!!!!!!!!!!!!!! Already STOPPED !!!!!!!!!!!!!!!!!!", self.iteration, self.name)

    def get_CnC_addr(self):
        if self.cnc_addr:
            return self.cnc_addr
        elif len(self.cnc_report)>0: # the first report is the cnc report
            if len(self.cnc_report[0])>0: #the first item of the tuple is the IP[:port]
                    return self.cnc_report[0][0]
        else:
            return ""
    
    def serialize_cnc_info(self, info, filename=CNCS_FILE, mapping={"SUC":"live_comm"}, fieldnames = None):
        global cncFields
        if len(info)==0:
            manager_print("Nothing or serialize!")
            return
        d1 = info[0][1].copy()
        d1['sample_name'] = self.name
        if len(info)>1:
            d1['misc'] = info[1:]
        row = prepare_row(info[0][0],d1,mapping)
        now = datetime.now()
        date_time = now.strftime("%m-%d-%Y_%H:%M:%S")
        row["timestamp"] = date_time
        cnc_file = self.abs_path + os.sep + filename
        if not fieldnames:
            fieldnames = cncFields
        write_to_csv(row,cnc_file,fieldnames)
    
    def prepare_info(self, comms, iteration_target_cnc_ip, result):
        info = result
        msg = ""
        if comms:
            if isinstance(comms,list):
                msg = "successful"
                manager_print(iteration_target_cnc_ip, "is not the most frequent address!")
                info = [(iteration_target_cnc_ip,{"SYN":comms}),("Not the most frequent",)]
            elif comms>0:
                msg = "successful"
                if len(result)>=2:
                    result[1] = [("verified_success", "True"),]
                else:
                    result.append([("verified_success", "True"),])
                info = result
            else:
                msg = "unsuccessful"
            manager_print("connection to", result[0][0], "was", msg, comms)
            manager_print("WARNING, successful connections can still be FP")
        return info
