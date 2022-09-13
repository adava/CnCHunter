#!/bin/bash
if ! sudo grep "bionic main universe" /etc/apt/sources.list; then echo "deb http://archive.ubuntu.com/ubuntu bionic main universe" >> /etc/apt/sources.list;fi
if ! sudo grep "bionic-security main universe" /etc/apt/sources.list; then echo "deb http://archive.ubuntu.com/ubuntu bionic-security main universe" >> /etc/apt/sources.list;fi
if ! sudo grep "bionic-updates main universe" /etc/apt/sources.list; then echo "deb http://archive.ubuntu.com/ubuntu bionic-updates main universe" >> /etc/apt/sources.list;fi
sudo apt update
sudo apt install make python2
sudo apt-get install -y pkg-config
sudo apt-get -y install python3-pip
sudo apt-get -y install zlib1g-dev
sudo apt-get -y install libglib2.0-dev
sudo apt-get -y install libpixman-1-dev
sudo apt-get -y install screen
sudo apt-get -y install dnsmasq
sudo apt-get -y install python-pip
sudo apt-get -y install tshark
sudo apt-get -y install unzip
sudo pip3 install pyelftools
sudo pip3 install pyshark
sudo pip3 install bs4
sudo pip3 install requests
sudo python3 -m pip install numpy
git submodule update --init --recursive
if [ ! -f "Qemu/build/mips-softmmu/qemu-system-mips" ];
then
	cd Qemu
	rm slirp/COPYRIGHT
	git checkout 87574621b18f86eab295a2c207e0b42c77b5dfa0
	# patch the memfd.c problem
	if ! grep "\/\*static int memfd_create(const char \*name, unsigned int flags)" util/memfd.c; 
	then
		sed 's/static int memfd_create(const char \*name\, unsigned int flags)/\/\*static int memfd_create(const char \*name\, unsigned int flags)/' util/memfd.c > res.tst;
		l_n1=`grep -n "\/\*static int memfd_create(const char \*name\, unsigned int flags)" res.tst | cut -f1 -d:`;
		end_ln=$(($l_n1+7));
		sed "$end_ln s/}/}\*\//" res.tst > res1.c;
		sed 's/#include \"qemu\/memfd\.h\"/\/\/#include \"qemu\/memfd\.h\"/' res1.c > util/memfd.c;
		rm res.tst res1.c
	fi
	# patch the user-exec.c ucontext problem
	ufiles="user-exec.c linux/user-exec.c linux-user/signal.c"
	for s in $ufiles;
	do
		if grep "struct ucontext" $s;
		then
        		sed 's/struct ucontext/ucontext_t/g' $s > res2.txt; cat res2.txt > $s; rm res2.txt

		fi
	done
	if ! grep "#include <sys\/sysmacros\.h>" qga/commands-posix.c;
	then
		sed "s/#include \"qemu\/base64\.h\"/#include \"qemu\/base64\.h\"\n#include <sys\/sysmacros\.h>/" qga/commands-posix.c > temp.txt; cat temp.txt > qga/commands-posix.c; rm temp.txt
	fi
	# configure and build qemu
	if [ ! -d "./build" ];
	then
        	mkdir build;
	fi
	cd build
		../configure --python=/usr/bin/python2.7 --target-list=mips-softmmu	
	make
	cd ../..
fi
sudo apt-get -y install python3-pip
sudo pip3 install pyelftools
sudo pip3 install pyshark
sudo pip3 install bs4
sudo pip3 install requests
sudo python3 -m pip install numpy
pip3 install jq
pip3 install pyzipper
pip3 install bs4
pip3 install requests
if ! sudo grep "nameserver 8.8.8.8" /etc/resolv.conf; then
	sudo sh -c 'echo "nameserver 8.8.8.8" >> /etc/resolv.conf'
fi
if ! sudo grep "nameserver 8.8.4.4" /etc/resolv.conf; then
        sudo sh -c 'echo "nameserver 8.8.4.4" >> /etc/resolv.conf'
fi
if ! grep "interface=br-wan" /etc/dnsmasq.conf;
then
	sudo sh -c 'echo "port=5353" >> /etc/dnsmasq.conf';
	sudo sh -c 'echo "interface=br-wan" >> /etc/dnsmasq.conf';
	sudo sh -c 'echo "dhcp-range=192.168.0.2,192.168.255.254,255.255.0.0,30m" >> /etc/dnsmasq.conf';
fi
if [ ! -d /usr/local/etc/qemu ];then sudo mkdir /usr/local/etc/qemu;fi
if [ ! -f "/usr/local/etc/qemu/bridge.conf" ];
then
	sudo sh -c 'echo "allow br-lan" >> /usr/local/etc/qemu/bridge.conf'
	sudo sh -c 'echo "allow br-wan" >> /usr/local/etc/qemu/bridge.conf'
fi
if grep "IF_INET=\"enp0s3\"" ./scripts/start_network.sh;
then
	var1=`ip route | grep "default" | head -1 | awk '{ print $5 }'`
	sed "s/IF_INET=\"enp0s3\"/IF_INET=\"$var1\"/g" ./scripts/start_network.sh > res4.txt;cat res4.txt > ./scripts/start_network.sh; rm res4.txt
fi
if [ -f malware/malware/sample.tar.xz ];then
	tar --to-stdout -xvf malware/malware/sample.tar.xz > malware/malware/sample;
	rm malware/malware/sample.tar.xz
fi
if [ -f filesystem/openwrt.zip ];then
	unzip filesystem/openwrt.zip -d filesystem/
	rm filesystem/openwrt.zip
fi
if [ -f kernels/openwrt-vmlinux.zip ];then
	unzip kernels/openwrt-vmlinux.zip -d kernels/
	rm kernels/openwrt-vmlinux.zip
fi
if [ ! -f cncs.csv ];
then 
	echo "sample_name,CnC_Addr,RST,SYN,DNS_Name,live_comm,misc,timestamp" > cncs.csv;
fi
if [ ! -f listened.csv ];
then 
	echo "sample_name,CnC_Addr,SYN,responses,misc,timestamp" > listened.csv;
fi

cd ..
