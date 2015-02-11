Analyze MPEG2TS stream and look for missing frames
==================================================

This program will analyze a stream of IPv6/UDP packets with MPEG2TS frames in
it. It will look at the PID and && values to determine if any frames are
missing.

Input is either via a PCAP file or packets can be captured live from a network
interface. Do note that you will have to join the multicast streams you are
interested in manually.
