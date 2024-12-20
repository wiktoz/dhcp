#!/bin/sh

ip netns add red
ip netns add blue

ip link add eth0-red type veth peer name eth0-blue
ip link set eth0-red netns red
ip link set eth0-blue netns blue



ip netns exec blue ip addr add 192.168.1.1/24 dev eth0-blue
ip netns exec blue ip route add 255.255.255.255 dev eth0-blue
ip netns exec blue ip link set lo up
ip netns exec blue ip link set eth0-blue up

sudo ip netns exec red ip link set eth0-red promisc on
ip netns exec red ip route add 255.255.255.255 dev eth0-red
ip netns exec red ip link set lo up
ip netns exec red ip link set eth0-red up

ip netns exec blue ip a
ip netns exec red ip a
