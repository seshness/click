/**
 * eth1 -> eth2
 */

// input :: FromDevice(eth1, PROMISC true, SNIFFER false);
// input :: FromDump(web-traffic-long.pcap, STOP false);
input :: KernelTap(10.0.29.1/24);
output :: ToDevice(eth1);
// output :: ToDump(output-traffic.pcap, ENCAP ETHER);
// I'm using the following port to log into the VM
// management :: FromDevice(eth0);

input
  // -> Strip(14)
  // -> EtherEncap(0x0800, 08:00:27:4a:fb:c1, 0a:00:27:00:00:02)
  -> c :: Classifier(12/0800, 12/0806)
  -> CheckIPHeader(14, VERBOSE true)
  -> ipf :: IPFilter(1 dst port 80, 1 src port 80, 0 all)
  -> r :: RandomSample(SAMPLE 0.5) /* Log (sample) good packets */
  -> t :: ToIPSummaryDump(good_packets.log, CONTENTS ip_src sport ip_dst dport ip_len payload)
  // SADDR SPORT DADDR DPORT FOUTPUT ROUTPUT
  -> ipr :: IPRewriter(pattern 169.229.49.107 - - - 0 1);

FromDevice(eth1)
  -> c1 :: Classifier(12/0800, 12/0806)
  -> CheckIPHeader(14, VERBOSE true)
  -> IPFilter(drop dst port 22, drop src port 22, allow all)
  -> ipr;

c1[1] -> Discard;

r[1]
  -> q :: Queue(20000);

ipr[0]
  -> q;

ipr[1]
  -> iq :: Queue(1024)
  -> input;

q
  -> Print(MAXLENGTH 40, CONTENTS HEX)
  -> output;

/* Log (sample) dropped packets */
ipf[1]
  -> RandomSample(SAMPLE 0.5)
  -> ToIPSummaryDump(bad_packets.log, CONTENTS ip_src sport ip_dst dport ip_len payload);

/* ARP requests are allowed to bypass the filter */
// c[1]
//   -> q;

/* ARP responses */
c[1]
  -> ARPResponder(0.0.0.0/0 FF:FF:FF:FF:FF:FF)
  -> Print("ARP reply")
  -> iq;

ControlSocket("TCP", 7777, VERBOSE true);
