/**
 * eth1 -> eth2
 */

// input :: FromDevice(eth1, SNIFFER false);
input :: FromDump(web-traffic-long.pcap, STOP true);
// output :: ToDevice(eth2);
output :: ToDump(output-traffic.pcap, ENCAP ETHER);
// I'm using the following port to log into the VM
// management :: FromDevice(eth0);

input
  // -> Strip(14)
  // -> EtherEncap(0x0800, 08:00:27:4a:fb:c1, 0a:00:27:00:00:02)
  -> c :: Classifier(12/0800)
  -> Print(MAXLENGTH 34, CONTENTS HEX)
  -> CheckIPHeader(14, VERBOSE true)
  -> ipf :: IPFilter(drop dst port 80, drop src port 80, allow all)
  -> Queue(20000)
  -> output;
