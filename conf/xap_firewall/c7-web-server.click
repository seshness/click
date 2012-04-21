ktun :: KernelTun(10.10.10.1/24);

KernelFilter(drop dev eth1:1);
// The following line prevents packets form reaching the Application Layer
// KernelFilter(drop dev tun0);

/**
 * The problem with the PlanetLab version is that it NATs outgoing traffic
 *  only. For the web server, incoming traffic needs to be "redirected" to the
 *  internal address.
 */
// input/output == 0 => tap device
// input/output == 1 => eth device
iapr :: IPAddrPairRewriter(pattern - 10.10.10.1 0 1);

iapr[0]
  -> Strip(14)
  -> qtun :: Queue
  -> Print("to the ktun:")
  -> ktun;

iapr[1]
  -> EtherEncap(0x0800, 00:25:90:09:e7:4c, 00:1e:f7:c0:97:40)
  -> qeth :: Queue
  -> ToDevice(eth1);

FromDevice(eth1)
  -> ceth :: Classifier(12/0806 20/0001, 12/0800, -)
  // MAKE SURE THIS IS A /32!!! or you'll be responsible for eventually bringing down the cX's >__<
  -> ARPResponder(169.229.49.158/32 00:25:90:09:e7:4c)
  -> qeth;

ceth[2] -> Discard;

ceth[1]
  -> CheckIPHeader(14)
  -> ipf :: IPFilter(allow ip host 169.229.49.158, deny all)
  -> Print("dst = ..158")
  -> [0]iapr;

ktun
  -> Print("from the ktun")
  -> CheckIPHeader(0)
  -> IPFilter(allow src ip host 10.10.10.1)
  -> [0]iapr;

ControlSocket("TCP", 7777, VERBOSE true);

/**
 * We'll need an iptables rule to prevent the OS from dropping our web server
 * bound packets:
 *   iptables -I INPUT --protocol tcp --in-interface eth1:1 --destination 169.229.49.158 --dport 8000 -j ACCEPT
 *   iptables -A OUTPUT --protocol tcp --tcp-flags RST --source 169.229.49.158 --sport 8000 -j DROP
 */
