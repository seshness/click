ktun :: KernelTun(10.10.10.1/24);
// ktun :: KernelTap(10.10.10.1/24, ETHER 00:11:22:33:44:55);
// client :: KernelTap(10.10.10.10/24, ETHER 66:77:88:99:AA:BB);

// client
//   -> cclient :: Classifier(12/0806 20/0001, -)
//   -> ARPResponder(0.0.0.0/0 00:1e:f7:c0:97:40)
//   -> q_client_tap :: Queue
//   -> client;

// cclient[1]
//   -> Discard;

KernelFilter(drop dev eth1:1);
// KernelFilter(drop dev tun0);

// input/output == 0 => tap device
// input/output == 1 => eth device
iapr :: IPAddrPairRewriter(pattern 169.229.49.158 - 1 0);

iapr[0]
  -> Strip(14)
  -> qtap :: Queue
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

// ipf[1] -> [0]iapr;

// 1 for request, 2 for reply
// ctap :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
// ktun -> Print(ktun) -> ctap;

// ctap[0]
//   -> ARPResponder(0.0.0.0/0 00:1e:f7:c0:97:40) // MAC of gateway 169.229.49.1
//   -> qtap; // skip the EtherEncap

// ctap[1] -> Discard;
// ctap[3] -> Discard;

ktun
  -> CheckIPHeader(0)
  -> IPFilter(allow src ip host 10.10.10.1)
  -> [0]iapr;

ControlSocket("TCP", 7777, VERBOSE true);
