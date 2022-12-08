echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

export DPDK_ENV="-c 0x1 -n 1 --vdev net_enetfec"

LD_PRELOAD=./libusect.so ./socket 0
