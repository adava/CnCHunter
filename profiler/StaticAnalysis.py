import subprocess
# import requests
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicTag

VALID_AV = ["ESET-NOD32", "Symantec", "AhnLab-V3", "Avira"]


class Static:
    def __init__(self, abs_path, hashVal, vt_key):
        self.file = abs_path + "/malware/malware/" + hashVal
        self.hash = hashVal
        self.vt_key = vt_key
        self.headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  RIoTMACOR"
        }
        self.vt_family = ""

    def get_file_type(self):
        # TODO: add cpu type
        return "mips"

    def get_file_size(self):
        fr = open(self.file, 'rb')
        size = len(fr.read())
        fr.close()
        return size

    # def virustotal(self):
    #     try:
    #         response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
    #                                 params = self.hash, headers = self.headers)
    #         json_response = response.json()
    #         print json_response
    #         found = False
    #         if json_response["positives"] > 0:
    #             for av in VALID_AV:
    #                 if json_response["scans"][av]["detected"]:
    #                     self.vt_family = json_response["scans"][av]["result"]
    #                     found = True
    #                     break
    #         if not found:
    #             self.vt_family = "Benign"
    #     except Exception as err:
    #         print err
    #         pass

    def ssdeep(self):
        fhash = subprocess.check_output(["ssdeep", self.file])
        splitted = fhash.split("\n")
        return splitted[1]

    def ssdeep_compare(self, master_ssdeep_file):
        output = subprocess.check_output(["ssdeep", "-m", master_ssdeep_file, self.file])
        return output

    def ascii_strings(self):
        output = subprocess.check_output(["strings", "-a", self.file])
        return output

    def unicode_strings(self):
        output = subprocess.check_output(["strings", "-a", "-el", self.file])
        return output

    def get_dynamic_libs(self):
        libs = set()
        with open(self.file, 'rb') as f:
            elf = ELFFile(f)
            for segment in elf.iter_segments():
                if segment.header.p_type != 'PT_DYNAMIC':
                    continue
                for t in segment.iter_tags():
                    if t.entry.d_tag == 'DT_NEEDED':
                        libs.add(str(t.needed))
        return libs

    def elf_header(self):
        output = subprocess.check_output(["readelf","-h",self.file])
        return output

    def program_header(self):
        output = subprocess.check_output(["readelf","-l",self.file])
        return output

    def section_header(self):
        output = subprocess.check_output(["readelf","-S",self.file])
        return output

    def symbols(self):
        output = subprocess.check_output(["readelf","-s",self.file])
        return output


