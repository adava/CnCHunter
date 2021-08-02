



https://user-images.githubusercontent.com/32986240/126545227-66adeb6b-7d3f-436e-8a2c-97a809147937.mp4



# CnC Hunter
CnCHunter is a fork of RiotMan, and it allows exploiting malware for active probing. This tool is presented in BlackHat USA 2021. For the presentation and the technical paper, see [CnCHunter: An MITM-Approach to Identify Live CnC Servers](https://www.blackhat.com/us-21/briefings/schedule/index.html#cnchunter-an-mitm-approach-to-identify-live-cnc-servers-23524).

Currently, you can use the tool for finding CnC servers or redirecting a CnC server's traffic to a custom address. In addition, using this tool, you would get the system call log and the traffic that the malware generates. The traffic
output is in pcap format, and the system call is the strace's output. For analyzing IoT malware, install the tool and analyze your malware binary by running the tool. You would only need to provide the malware sample (and candidate addresses for probing); no other configurations are needed after installing the tool.

# Installation
We are working on creating an installation script but meanwhile you can follow the steps below to install CnCHunter.
Every step and command required for the installation is given below. Please be patient and walk through the steps, you wouldn't need (hopefuly) to run any
other command or resolve any dependencies yourself.
## Installing OS
CnCHunter is tested on Ubuntu 18.04. RiotMan's initital prototype was built on top of Debian 8.3, and it was tested for Debian 8.11. However, CnCHunter was not tested on those operating systems. You can download a virtualbox image for Ubuntu 18.04 from [here](
https://sourceforge.net/projects/osboxes/files/v/vb/55-U-u/18.04/18.04.3/18.04.3VB-64bit.7z/download).


Turn on the VM. The OS is clean, so we will install every dependency we need in the next steps.
> Note: please do not move to the next steps before having a functional 18.04 (other OSes were not tested).

## Cloning the repository
You need to clone this repository with the **--recurisve** option because Qemu (the underlying emulator for analysis) is a sub module of this repo.
Please run:

    sudo apt-get install git
    git clone --recursive [THIS-REPO-URL]
> Note: run the first command only if you do not have git. 

At this point, you can't still compile Qemu. Please see the next section to install the dependencies.

## Dependencies
The following packages need to be installed for the Qemu compilation (gcc, g++, make and pkg-config are also required but installed by default):
    
    sudo apt-get install zlib1g-dev
    sudo apt-get install libglib2.0-dev
    sudo apt-get install -y libpixman-1-dev

The following are required for RiotMan:
    
    sudo apt-get install screen
    sudo apt-get install dnsmasq
    sudo apt-get install python-pip
    sudo apt-get install tshark
 
 dnsmasq installation terminates with error. It is because port 53, by default, is taken by the resolve service. Ignore the error at this point, we will change the port later on.

CnCHunter also relies on the following python libraries:
    
    sudo pip3 install pyelftools
    sudo pip3 install pyshark
    sudo pip3 install bs4
    sudo pip3 install requests
    sudo python3 -m pip install numpy

## Installing Qemu

The development of RiotMan was started in 2016, and at the time, the Qemu that was used was the following:
    
    cd Qemu
    git checkout 87574621b18f86eab295a2c207e0b42c77b5dfa0

At the time, Qemu needed to be modified to fix a few bugs:

https://git.qemu.org/?p=qemu.git;a=commit;h=75e5b70e6b5dcc4f2219992d7cffa462aa406af0

Comment out:

    Qemu/util/memfd.c:43 (inclusion)
    Qemu/util/memfd.c:47 52 (declaration)

https://github.com/Ebiroll/qemu_esp32/issues/12

After you completed the above steps, you're ready to compile Qemu. Compile by:

    cd Qemu
    mkdir build
    cd build
    ../configure
    make

> the **build** folder name should not change, CnCHunter looks in Qemu/build for the Qemu executable.

## Network configuration
We have scripts that does the required configuration before a malware sample analysis but still there are some basic configurations
that need to be done manually.

Set the host network interface in the start_network.sh script (it should be correct if you downloaded the VM image that we mentioned above):

    ip link show # find the host network interface name
    vi scripts/start_network.sh # change the IF_INET variable value

Set the name servers (If you don't, the name resolution fails once the emulation starts):

    vi /etc/resolve.conf # add lines below
    nameserver 8.8.8.8
    nameserver 8.8.4.4

Configure dnsmasq DHCP server by changing the DNS port to 5353 and adding the following lines to /etc/dnsmasq.conf:
    
    port=5353
    interface=br-wan
    dhcp-range=192.168.0.2,192.168.255.254,255.255.0.0,30m
    
Configure Qemu bridging by creating "/usr/local/etc/qemu/bridge.conf". You'd need to create the qemu directory and the file. Add the following lines to the file:
    
    allow br-lan
    allow br-wan

# Execution
If you completed the **Installation** steps, you're ready to execute CnCHunter and analyze an IoT malware. Currently, only MIPS 32BE samples can be analyzed.
You would need three inputs for your analyis:
* **a malware sample**: we placed a gafgyt malware sample (the old malware sample we mention in our BlackHat 2021 paper) in the malware/malware folder. Extract by

      cd malware/malware
      tar -xvf sample.tar.xz
      rm sample.tar.xz
* **a filesystem**: IoT devices have different dependencies, you either have the filesystem of the IoT device you're interested in analyzing, or you can use 
the one we used for our analysis published in BlackHat 2021. The file is available in the "filesystem" folder. You need to unzip the file before running the tool.
* **a kernel**: Again this is the Kernel of your target IoT device. You can use 
the one we used for our analysis published in BlackHat 2021. The file is available in the "kernel" folder. You need to unzip the file before running the tool.
 
After providing the above inputs, you can start the analysis. CnCHunter needs root permissions. You can use CnCHunter without arguments to find the CnC Server of the current malware binary, or you can MitM (redirect) the malware's CnC traffic to a custom address:

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
