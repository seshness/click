/**
 * eth1 -> eth2
 */

input :: FromDevice(eth1, SNIFFER false);
// input :: FromDump(web-traffic-long.pcap, STOP true);
output :: ToDevice(eth2);
// output :: ToDump(output-traffic.pcap, ENCAP ETHER);
// I'm using the following port to log into the VM
// management :: FromDevice(eth0);

input
  -> Queue(20000)
  -> output;
