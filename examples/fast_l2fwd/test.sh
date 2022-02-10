#! /bin/sh
#clean
ip link del dev veth0
ip link del dev veth2
ip link del dev veth4
ip link del dev veth6
ip link del dev veth8
ip link del dev veth10

ip link add dev veth0 type veth peer veth1
ifconfig veth0 up
ip netns add net1
ip link set veth1 netns net1
ip netns exec net1 ifconfig veth1 192.168.1.1
ip link add dev veth2 type veth peer veth3
ifconfig veth2 up
ip netns add net3
ip link set veth3 netns net3
ip netns exec net3 ifconfig veth3 192.168.1.2
ip link add dev veth4 type veth peer veth5
ifconfig veth4 up
ip netns add net5
ip link set veth5 netns net5
ip netns exec net5 ifconfig veth5 192.168.5.1
ip link add dev veth6 type veth peer veth7
ifconfig veth6 up
ip netns add net7
ip link set veth7 netns net7
ip netns exec net7 ifconfig veth7 192.168.5.2
ip link add dev veth8 type veth peer veth9
ifconfig veth8 up
ip netns add net9
ip link set veth9 netns net9
ip netns exec net9 ifconfig veth9 192.168.9.1
ip link add dev veth10 type veth peer veth11
ifconfig veth10 up
ip netns add net11
ip link set veth11 netns net11
ip netns exec net11 ifconfig veth11 192.168.9.2