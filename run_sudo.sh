cargo build --release
ret=$?
if [[ $ret -ne 0 ]]; then
    exit $ret
fi
sudo target/release/icmp-tuntap &
pid=$!
sudo ip addr add 10.0.0.0/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
