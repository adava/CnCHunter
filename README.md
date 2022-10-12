



https://user-images.githubusercontent.com/32986240/126545227-66adeb6b-7d3f-436e-8a2c-97a809147937.mp4



# CnC Hunter
CnCHunter can find C2 servers of IoT malware, and allows exploiting malware for active probing. This tool is presented in BlackHat USA 2021. For the presentation and the technical paper, see [CnCHunter: An MITM-Approach to Identify Live CnC Servers](https://www.blackhat.com/us-21/briefings/schedule/index.html#cnchunter-an-mitm-approach-to-identify-live-cnc-servers-23524). An extension of the original tool was used in the measurement study [MalNet: A binary-centric network-level profiling of IoT Malware
](https://www.cs.ucr.edu/~adava003/MalNet_IMC2022.pdf) that is published in IMC 2022. If you are interested in our datasets, please see our [Wiki page](https://github.com/adava/CnCHunter/wiki).

Currently, you can use the tool for finding CnC server or redirecting the CnC server traffic to a custom address. In addition, using this tool, you would get the system call log and the traffic that the malware generates. The traffic output is in pcap format, and the system call is strace output. For analyzing IoT malware, install the tool and analyze your malware binary by running the tool. You would only need to provide the malware sample (and candidate addresses for probing); no other configurations are needed after installing the tool.

# Installation
There is an installer that is tested for Ubuntu LTS 20.04. Install your operating system, then run the following:

    git clone --recursive [THIS-REPO-URL]
    cd CnCHunter
    ./install.sh


 
After the installation, you need to provide the samples for analysis. There is a sample in the malware/malware directory that allows you run, and test the tool. The C2 address of that sample is 138.197.104.187:23.

CnCHunter needs root permissions (very important, don't simply run the tool). You can use CnCHunter without arguments to find the CnC Server of the current malware binary, or you can MitM (redirect) the malware's CnC traffic to a custom address:

     sudo su
     python3 ./run.py [-t IP:PORT]

The execution generates a log file in the root folder that shows the progress. After the completion of the analysis, other analysis results are available under the analysis folder.

# Project Structure
* scripts: configuration scripts
* manager: source code for malware emulation and dynamic analysis
* kernels: the openwrt-malta-be-vmlinux.elf and others
* filesystem: openwrt-malta-be-root.ext4 with the dependencies
* analysis: for the results
* malware/malware: **your malware samples go here**
* profiler: network and static analysis modules 
* Qemu: a qemu clone from commit 87574621b18f86eab295a2c207e0b42c77b5dfa0

# Emulated VM
For any reason, if you needed to inspect the emulated machine (that the malware runs on). You can connect to the analysis session:

    screel -ls
    screen -r [CnCHunter_INSTANCE_ID]

# Supported Architectures
Currently, we only support the MIPS BE 32b binaries. We are working on providing support for more architectures, please let us know if you have a stable suite of filesystem, Kernel and configuration for an architecture.

# Disclaimer
This tool is an academic tool used for research purposes. Users must comply with the regulations, and avoid sending unsolicited traffic to legal entities that oppose doing so. Please use the tool responsibly. We do not take any responsibility in misusing this tool.
