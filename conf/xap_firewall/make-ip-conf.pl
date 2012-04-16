#! /usr/bin/perl -w

# make-ip-conf.pl -- make a Click IP router configuration
# Robert Morris, Eddie Kohler, David Scott Page
#
# Copyright (c) 1999-2000 Massachusetts Institute of Technology
# Copyright (c) 2002 International Computer Science Institute
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, subject to the conditions
# listed in the Click LICENSE file. These conditions include: you must
# preserve this copyright notice, and you cannot mention the copyright
# holders in advertising related to the Software without their permission.
# The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
# notice is a summary of the Click LICENSE file; the license in that file is
# legally binding.

# Make a Click IP router configuration.  This script generates a
# configuration using PollDevices. You can change it to use
# FromDevices; see the comment above the $ifs array, below.  The
# output is intended for the Linux kernel module; however, by making
# the change from PollDevices to FromDevices, and setting $local_host
# appropriately, the configuration will also work at userlevel.

# --------------------------- Begin configuration ----------------------------

# Change this array to suit your router.
# One line per network interface, containing:
#  The interface name;
#  Whether the interface can use polling (1 = polling, 0 = no polling);
#  The router's IP address on that interface;
#  The netmask on that interface; and
#  The router's Ethernet address on that interface.
# This setup for blackisle -> plebic -> darkstar.
my $ifs = [ [ "eth1", 1, "169.229.49.158", "255.255.255.0", "00:25:90:09:e7:4c" ],
            [ "eth0", 1, "169.229.49.192", "255.255.255.0", "00:1b:21:44:04:68" ],
#           [ "eth2", 1, "2.0.0.1", "255.0.0.0", "00:00:C0:8A:67:EF" ],
           ];

# This used for testing purposes at MIT.
if ($#ARGV >= 0) {
  $ifs = [];
  for ($i = 0; $i < $ARGV[0]; $i++) {
    push @$ifs, [ "eth" . $i, 1, "1.0.0.2", "255.0.0.0", "00:00:c0:8a:67:ef" ];
  }
}

# Static routes to hosts/networks beyond adjacent networks specified in $ifs.
# One line per route, containing:
#   The destination address (host or network);
#   The mask;
#   The gateway IP address (next hop);
#   The output network interface name.
# A default route (mask 0.0.0.0) can be specified as the last entry.
my $srts = [ [ "0.0.0.0", "0.0.0.0", "18.26.4.1", "eth0" ]
	   ];

# Set to, e.g., "Print(toh) -> Discard" for user-level.
my $local_host = "ToHost";

# Set to 1 if you want the configuration to handle ICMP echo requests itself.
my $handle_pings = 0;

# --------------------------- End of configuration ---------------------------

my $nifs = $#$ifs + 1;
my $nsrts = $#$srts + 1;

print "// Generated by make-ip-conf.pl\n";

my $i;
for($i = 0; $i < $nifs; $i++){
    printf("// %s %s %s\n",
           $ifs->[$i]->[0],
           $ifs->[$i]->[2],
           $ifs->[$i]->[4]);
}

# Set up the routing table.
my(@routes, @interfaces);

# For delivery to the local host
for($i = 0; $i < $nifs; $i++){
    my $ii = ip2i($ifs->[$i]->[2]);
    my $mask = ip2i($ifs->[$i]->[3]);

    push @routes, sprintf("%s/32 0", i2ip($ii));# This host.

    my $dirbcast = ($ii & $mask) | ~$mask;	# Directed broadcast.
    push @routes, sprintf("%s/32 0", i2ip($dirbcast));

    push @interfaces, $ifs->[$i]->[2] . '/' . $ifs->[$i]->[3];

    push @routes, sprintf("%s/32 0", i2ip($ii & $mask));
    						# Directed broadcast (obsolete).
}

# For forwarding to connected networks
for($i = 0; $i < $nifs; $i++){
    my $ii = ip2i($ifs->[$i]->[2]);
    my $mask = ip2i($ifs->[$i]->[3]);
    push @routes, sprintf("%s/%s %d",
           i2ip($ii & $mask),
           i2ip($mask),
           $i + 1);
}

# For remaining broadcast addresses
push @routes, "255.255.255.255/32 0.0.0.0 0";	# Limited broadcast.

push @routes, "0.0.0.0/32 0";			# Limited broadcast (obsolete).

# For forwarding to static routes
for ($i = 0; $i < $nsrts; $i++) {
    my $ii = ip2i($srts->[$i]->[0]);
    my $mask = ip2i($srts->[$i]->[1]);
    my $gw = $srts->[$i]->[2];
    my $ifname = $srts->[$i]->[3];
    my $out;
    for ($out = 0; $out < $nifs; $out++) {
	last if $ifs->[$out]->[0] eq $ifname;
    }
    die if $out >= $nifs;
    push @routes, sprintf("%s/%s %s %d",
	i2ip($ii & $mask), i2ip($mask),
        $gw, $out + 1);
}

print "\n// Shared IP input path and routing table\n";
print "ip :: Strip(14)
    -> CheckIPHeader(INTERFACES ", join(' ', @interfaces), ")
    -> rt :: StaticIPLookup(\n\t", join(",\n\t", @routes), ");\n";

# Link-level devices, classification, and ARP
print "\n// ARP responses are copied to each ARPQuerier and the host.\n";
printf("arpt :: Tee(%d);\n", $nifs + 1);
for($i = 0; $i < $nifs; $i++){
    my $devname = $ifs->[$i]->[0];
    my $ip = $ifs->[$i]->[2];
    my $ena = $ifs->[$i]->[4];
    my $paint = $i + 1;
    my $fromdevice = ($ifs->[$i]->[1] ? "PollDevice" : "FromDevice");
    print <<"EOD;";

// Input and output paths for $devname
c$i :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
$fromdevice($devname) -> c$i;
out$i :: Queue(200) -> todevice$i :: ToDevice($devname);
c$i\[0] -> ar$i :: ARPResponder($ip $ena) -> out$i;
arpq$i :: ARPQuerier($ip, $ena) -> out$i;
c$i\[1] -> arpt;
arpt[$i] -> [1]arpq$i;
c$i\[2] -> Paint($paint) -> ip;
c$i\[3] -> Print("$devname non-IP") -> Discard;
EOD;
}

# Local delivery path.
print "\n// Local delivery\n";
print "toh :: $local_host;\n";
print "arpt[$nifs] -> toh;\n";
if ($handle_pings) {
    print <<"EOD;";
rt[0] -> IPReassembler -> ping_ipc :: IPClassifier(icmp type echo, -);
ping_ipc[0] -> ICMPPingResponder -> [0]rt;
ping_ipc[1] -> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> toh;
EOD;
} else {
    print "rt[0] -> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> toh;\n";
}

# Forwarding path.
for($i = 0; $i < $nifs; $i++){
    my $i1 = $i + 1;
    my $ipa = $ifs->[$i]->[2];
    my $devname = $ifs->[$i]->[0];
    print <<"EOD;";

// Forwarding path for $devname
rt[$i1] -> DropBroadcasts
    -> cp$i :: PaintTee($i1)
    -> gio$i :: IPGWOptions($ipa)
    -> FixIPSrc($ipa)
    -> dt$i :: DecIPTTL
    -> fr$i :: IPFragmenter(1500)
    -> [0]arpq$i;
dt$i\[1] -> ICMPError($ipa, timeexceeded) -> rt;
fr$i\[1] -> ICMPError($ipa, unreachable, needfrag) -> rt;
gio$i\[1] -> ICMPError($ipa, parameterproblem) -> rt;
cp$i\[1] -> ICMPError($ipa, redirect, host) -> rt;
EOD;
}


sub ip2i {
    my($ip) = @_;
    my @a = split(/\./, $ip);
    my $i = ($a[0] << 24) + ($a[1] << 16) + ($a[2] << 8) + $a[3];
    return($i);
}
sub i2ip {
    my($i) = @_;
    my $a = ($i >> 24) & 0xff;
    my $b = ($i >> 16) & 0xff;
    my $c = ($i >> 8) & 0xff;
    my $d = $i & 0xff;
    return sprintf("%d.%d.%d.%d", $a, $b, $c, $d);
}
