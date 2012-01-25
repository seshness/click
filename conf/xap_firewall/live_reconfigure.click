/**
 * eth1 -> eth2
 */

input :: FromDevice(eth1, PROMISC true, SNIFFER false);
// input :: FromDump(web-traffic-long.pcap, STOP false);
output :: ToDevice(eth2);
// output :: ToDump(output-traffic.pcap, ENCAP ETHER);
// I'm using the following port to log into the VM
// management :: FromDevice(eth0);

input
  // -> Strip(14)
  // -> EtherEncap(0x0800, 08:00:27:4a:fb:c1, 0a:00:27:00:00:02)
  -> Print(MAXLENGTH 40, CONTENTS HEX)
  -> c :: Classifier(12/0800, 12/0806)
  -> CheckIPHeader(14, VERBOSE true)
  -> ipf :: IPFilter(1 dst port 80, 1 src port 80, 0 all)
  -> q :: Queue(20000)
  -> output;

/* Log dropped packets */
ipf[1]
  -> PacketLogger2(NBYTES 34)
  -> Discard;

/* ARP requests subvert filter */
c[1]
  -> q;

ControlSocket("TCP", 7777, VERBOSE true);
