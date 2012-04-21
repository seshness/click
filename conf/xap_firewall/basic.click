/**
 * eth1 -> eth2
 */

// input :: FromDevice(eth1, SNIFFER false);
input :: FromDump(~/web-traffic-long.pcap, STOP false);
// output :: ToDevice(eth2);
output :: ToDump(~/output-traffic.pcap, ENCAP ETHER);
// I'm using the following port to log into the VM
// management :: FromDevice(eth0);

input
  -> ipf :: IPFilter(0 all)
  -> Queue(20000)
  -> output;

ipf[1]
  -> Discard;

ControlSocket("TCP", 7777, VERBOSE true);
