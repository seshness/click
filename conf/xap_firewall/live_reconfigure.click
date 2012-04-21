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
  -> c :: Classifier(12/0800, 12/0806)
  -> CheckIPHeader(14, VERBOSE true)
  -> ipf :: IPFilter(0 all)
  -> r :: RandomSample(SAMPLE 0.5) /* Log (sample) good packets */
  -> t :: ToIPSummaryDump(good_packets.log, CONTENTS ip_src sport ip_dst dport ip_len payload)
  -> q :: Queue(20000);

r[1]
  -> q;

q
  -> Print(MAXLENGTH 40, CONTENTS HEX)
  -> output;

/* Log (sample) dropped packets */
ipf[1]
  -> RandomSample(SAMPLE 0.5)
  -> ToIPSummaryDump(bad_packets.log, CONTENTS ip_src sport ip_dst dport ip_len payload);

/* ARP requests are allowed to bypass the filter */
c[1]
  -> q;

ControlSocket("TCP", 7777, VERBOSE true);
