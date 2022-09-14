# This parameter will be passed to masscan. It sets the ports that we scan. Our configuration is using these ports plus the CnC port
scanning_ports = "45,1024,9506,12842,6524,1791,666,5555,200,81,123,606,1312,6524,7854,21795,39752,42516,16782,6667,55650,39490,51675" #list of ports comma separated (no space)
# We use this subnet mask value to scan the neighbors of a CnC
DEFAULT_MASK = 0xfffffe00 # this is 255.255.254.0
# This parameter will be passed to masscan. Experiments show higher rates will have a high false positive.
scanning_rate = 100
# This variable sets the total number of IPs that would be selected based on the scanning result
# The final MitM instances will be based on the number of selected samples; in short, it will be probaly (the number of selected IPs)/(number of selected samples)
# Based on 140 seconds analysis and MalwareBazaar dataset, we can afford ~ 500 a day
MitM_budget = 20
# The file where we store the CnC addresses; you need to change this value in download_analyze.sh script too
CNCS_FILE = "cncs.csv"
# The file where we store the result of port scanning and MitMing
SUBENTS_FILE = "subnets_scan.csv"
# The file where we store the communication patterns (for live CnCs) after analyzing samples; you need to change the value in store_pattern.sh too
PATTERN_FILE = "cnc_patterns.csv"
# The file where we store the communication patterns for MitMed severs
MitM_PATTERN_FILE = "MitM_cnc_patterns.csv"
# The file where we temporarily store the MitM results
TEMP_FILE = "temp_subnet.csv"
# The file where the result of whether the MitMed target successfully responded is stored
MitM_RESULT_FILE ="listened.csv"
# The number of samples used for MitM
PARAM_SAMPLE_SELECT = 2
# The folder where malware samples are stored after analysis
MALWARE_DATABASE = "./malware/backup"
# The fileds names of SUBENTS_FILE; DO NOT CHANGE IT!
fieldnames_subnets = ["subnet", "Timestamp_Scanned", "CnC_Addr", "TimeStamp_MitMed", "Live_IPs", "Selected_For_MitM_IPs", "Selected_Samples"]
# The fileds names of CNCS_FILE; DO NOT CHANGE IT!
cncFields = ["sample_name", "CnC_Addr", "RST", "SYN", "DNS_Name", "live_comm", "misc", "timestamp"]
# The fileds names of PATTERN_FILE and MitM_PATTERN_FILE; DO NOT CHANGE IT!
fieldnames_patterns = ["Hash", "iteration", "src_port", "cnc_addr", "pattern"]
# The fileds names of MitM_RESULT_FILE; DO NOT CHANGE IT!
fieldnames_listend_cncs = ["sample_name", "CnC_Addr", "SYN", "responses", "misc", "timestamp"]
# The number of parallel instances used for analysis; don't increase this TODO: need to resolve DHCP problem with more parallel instances
PARALLEL_INSTANCES = 1 
# The amount of time we spend on analyzing a single sample
EXPERIMENT_TIME = 140
# The maximum amount of time we spend on are allowed to wait and analyze (in case something goes wrong)
ULTIMATE_TIMER = 1000
# A flag to activate cross experiments; with this flag, similar samples would be used for MitMing a live CnC server
CROSS_EXPERIMENT = True
