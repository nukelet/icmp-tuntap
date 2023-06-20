cargo build --release
ret=$?
if [[ $ret -ne 0 ]]; then
    exit $ret
fi
sudo setcap "cap_net_admin=eip" target/release/icmp-tuntap
target/release/icmp-tuntap &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
