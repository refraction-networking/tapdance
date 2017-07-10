#!/bin/bash

# COREBASE: the first core to use
# CORECOUNT: the total number of cores to use
#
COREBASE=0
CORECOUNT=12

if [ $(id -u) -ne 0 ]; then
    echo "$0 must be run as sudo"
    exit 1
fi

# Some paths are relative to this script
SCRIPTDIR=$(/bin/readlink -f $(/usr/bin/dirname $(/usr/bin/which "$0")))

make_gobbler_fifos() {

    local core_cnt=$1
    local core_base=$2
    local curr_core=0

    while [ "${curr_core}" -lt "${core_cnt}" ]; do
	local core_num=$((curr_core + core_base))

	local p="/tmp/tapdance-reporter-${core_num}.fifo"
	if [ ! -p "${p}" ]; then
	    sudo rm -f "${p}"
	    sudo mkfifo "${p}"
	fi

	local curr_core=$((curr_core + 1))
    done
}

make_gobbler_fifos "${CORECOUNT}" "${COREBASE}"

echo "Creating /mnt/huge and mounting as hugetlbfs"
sudo mkdir -p /mnt/huge
grep -s '/mnt/huge' /proc/mounts > /dev/null
if [ $? -ne 0 ] ; then
        sudo mount -t hugetlbfs nodev /mnt/huge
fi

echo "Setting 2048 hugepages"
echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

echo "Inserting PF_RING module"
sudo insmod pfring-framework/kernel/pf_ring.ko


DEVICE=ens15f1
echo "Inserting uio_pci_generic"
sudo modprobe uio_pci_generic
echo "Binding NIC to uio_pci_generic"
sudo ./dpdk_nic_bind.py -b i40e 0000:03:00.1
sudo ifconfig $DEVICE up
# OR, if you have a card that needs the ixgbe driver:
#DEVICE=enp1s0f0
#echo "Inserting uio_igb from dpdk"
#sudo modprobe uio
#sudo insmod $HOME/dpdk-16.04/build/kmod/igb_uio.ko
#echo "Binding NIC to uio_igb"
#sudo ./dpdk_nic_bind.py -b ixgbe 0000:01:00.0
#sudo ifconfig $DEVICE up


echo "Setting up tun0 device"
ip tuntap add mode tun tun0
ip tuntap add mode tun tun1
ip tuntap add mode tun tun2
ip tuntap add mode tun tun3
ip tuntap add mode tun tun4
ip tuntap add mode tun tun5
ip tuntap add mode tun tun6
ip tuntap add mode tun tun7
ip tuntap add mode tun tun8
ip tuntap add mode tun tun9
ip tuntap add mode tun tun10
ip tuntap add mode tun tun11
ip tuntap add mode tun tun12
ip tuntap add mode tun tun13
ip tuntap add mode tun tun14
ip tuntap add mode tun tun15

echo "Turning off RP filter"
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.tun0.rp_filter=0
sysctl -w net.ipv4.conf.tun1.rp_filter=0
sysctl -w net.ipv4.conf.tun2.rp_filter=0
sysctl -w net.ipv4.conf.tun3.rp_filter=0
sysctl -w net.ipv4.conf.tun4.rp_filter=0
sysctl -w net.ipv4.conf.tun5.rp_filter=0
sysctl -w net.ipv4.conf.tun6.rp_filter=0
sysctl -w net.ipv4.conf.tun7.rp_filter=0
sysctl -w net.ipv4.conf.tun8.rp_filter=0
sysctl -w net.ipv4.conf.tun9.rp_filter=0
sysctl -w net.ipv4.conf.tun10.rp_filter=0
sysctl -w net.ipv4.conf.tun11.rp_filter=0
sysctl -w net.ipv4.conf.tun12.rp_filter=0
sysctl -w net.ipv4.conf.tun13.rp_filter=0
sysctl -w net.ipv4.conf.tun14.rp_filter=0
sysctl -w net.ipv4.conf.tun15.rp_filter=0


# Dunno if we need all of these but...eh. Memory is cheap.
echo "Setting TCP/net memory"
echo 12582912 > /proc/sys/net/core/wmem_max
echo 12582912 > /proc/sys/net/core/wmem_default
echo 12582912 > /proc/sys/net/core/rmem_max
echo 12582912 > /proc/sys/net/core/rmem_default
echo '10240 87380 12582912' > /proc/sys/net/ipv4/tcp_wmem
echo '10240 87380 12582912' > /proc/sys/net/ipv4/tcp_rmem
echo '8388608 12582912 16777216' > /proc/sys/net/ipv4/tcp_mem



echo "Adding rule for tun0"
ip rule add iif tun0 lookup custom
ip route add local 0.0.0.0/0 dev tun0 table custom
ip rule add iif tun1 lookup custom
ip route add local 0.0.0.0/0 dev tun1 table custom
ip rule add iif tun2 lookup custom
ip route add local 0.0.0.0/0 dev tun2 table custom
ip rule add iif tun3 lookup custom
ip route add local 0.0.0.0/0 dev tun3 table custom
ip rule add iif tun4 lookup custom
ip route add local 0.0.0.0/0 dev tun4 table custom
ip rule add iif tun5 lookup custom
ip route add local 0.0.0.0/0 dev tun5 table custom
ip rule add iif tun6 lookup custom
ip route add local 0.0.0.0/0 dev tun6 table custom
ip rule add iif tun7 lookup custom
ip route add local 0.0.0.0/0 dev tun7 table custom
ip rule add iif tun8 lookup custom
ip route add local 0.0.0.0/0 dev tun8 table custom
ip rule add iif tun9 lookup custom
ip route add local 0.0.0.0/0 dev tun9 table custom
ip rule add iif tun10 lookup custom
ip route add local 0.0.0.0/0 dev tun10 table custom
ip rule add iif tun11 lookup custom
ip route add local 0.0.0.0/0 dev tun11 table custom
ip rule add iif tun12 lookup custom
ip route add local 0.0.0.0/0 dev tun12 table custom
ip rule add iif tun13 lookup custom
ip route add local 0.0.0.0/0 dev tun13 table custom
ip rule add iif tun14 lookup custom
ip route add local 0.0.0.0/0 dev tun14 table custom
ip rule add iif tun15 lookup custom
ip route add local 0.0.0.0/0 dev tun15 table custom

echo "Loading forge_socket"
sudo rmmod forge_socket
sudo insmod $HOME/forge_socket/forge_socket.ko

echo "Restarting Squid"
sudo service squid restart

if [ "$1" != "--nozerocopy" ] ; then
    echo "LOADING ZERO-COPY DRIVERS"
    echo "DO NOT LOAD THESE FOR NON-ZC VERSIONS OF THE STATION"

    echo "Loading zero-copy i40e driver"
    cd $SCRIPTDIR/pfring-framework/drivers/intel/i40e/i40e-1.5.18-zc/src/
    sudo ./load_driver.sh
# OR, if you have a card that needs the ixgbe driver:
#    echo "Loading zero-copy ixgbe driver"
#    cd $SCRIPTDIR/pfring-framework/drivers/intel/ixgbe/ixgbe-4.1.5-zc/src/
#    sudo ./load_driver.sh

    echo "Stopping the IRQ balancer..."
    sudo service irqbalance stop

    echo ""
    echo ""
    echo "TO START THE STATION, RUN THE FOLLOWING COMMANDS IN SEPARATE SCREENS:"
    echo ""
    echo "cd $SCRIPTDIR/pfring-framework/userland/examples_zc; \\"
    echo "        sudo ./zbalance_ipc -i zc:$DEVICE -c 99 -n $CORECOUNT -m 1 -g 1"
    echo ""
    echo "cd $SCRIPTDIR/gobbler; ./gobbler"
    echo ""
    echo "cd $SCRIPTDIR/pfring-framework/userland/examples/; \\"
    echo "        sudo RUST_BACKTRACE=1 ./zc_tapdance -c 99 -o $COREBASE -n $CORECOUNT -l 5"
    echo ""
else
    echo ""
    echo ""
    echo "TO START THE STATION, RUN THE FOLLOWING COMMANDS IN SEPARATE SCREENS:"
    echo ""
    echo "cd $SCRIPTDIR/gobbler; ./gobbler"
    echo ""
    echo "cd $SCRIPTDIR/pfring-framework/userland/examples/; \\"
    echo "        sudo RUST_BACKTRACE=1 ./tapdance -i $DEVICE -c 7 -o $COREBASE -n $CORECOUNT -l 5"
fi
