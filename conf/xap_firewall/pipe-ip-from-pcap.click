/**
 * Allow pcap files without an Ethernet header to be passed through
 * pcap -> vboxnet1
 */

input :: FromDump(web-traffic-long.pcap, STOP true);
output :: ToDevice(vboxnet1);

input
  -> Strip(14)
  -> EtherEncap(0x0800, 0a:00:27:00:00:01, 08:00:27:71:16:d2)
  -> Print(MAXLENGTH 40, CONTENTS HEX)
  -> output;
