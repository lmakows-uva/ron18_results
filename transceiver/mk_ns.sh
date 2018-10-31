for i in 38;do

# place each vlan* interface inside a separate namespace

if="vlan3${i}"
NSNAME="${if}_ns"

ip netns del $NSNAME

ip netns add $NSNAME && \
ip link set $if netns $NSNAME && \
ip netns exec $NSNAME ip link set dev $if up && \
ip netns exec $NSNAME ip addr add 10.${i}.0.10/24 dev $if && \
ip netns exec $NSNAME ip route add 0.0.0.0/0 via 10.${i}.0.1

done
