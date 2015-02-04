#!/usr/bin/python

import dpkt


f = file('tvstream.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

class MPEG2TS(dpkt.Packet):
    __hdr__ = (
            ('syncb', 'B', 0),
            ('stuff', 'H', 0),
            ('stuff2', 'B', 0)
            )

class tjong:
    def __init__(self):
        self.data = {}

    def parse_frame(self, frame):
        res = MPEG2TS(frame)

        # parse headers out of that stupid frame
        ts_tei = (res.stuff & 0x8000) >> 15
        ts_pusi = (res.stuff & 0x4000) >> 14
        ts_tp = (res.stuff & 0x2000) >> 13
        ts_pid = (res.stuff & 0x1FFF) >> 0
        ts_tsc = (res.stuff2 & 0xC0) >> 6
        ts_afc = (res.stuff2 & 0x30) >> 4
        ts_cc = (res.stuff2 & 0xF) >> 0

        return ts_pid, ts_cc



    def process_packet(self, packet):
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP6:
            return
        ip = eth.data

        if ip.nxt != dpkt.ip.IP_PROTO_UDP:
            return
        udp = ip.data
        data = udp.data
        if len(data) < 188:
            # TODO: SCREAM!?
            return

        if ip.dst not in self.data:
            self.data[ip.dst] = {}
        group = self.data[ip.dst]

        FRAME_LENGTH = 188
        i = 0
        while i < len(data) and i + FRAME_LENGTH <= len(data):
            # TODO: loop over all frames in packet
            frame = data[i:i+FRAME_LENGTH]
            i += FRAME_LENGTH

            ts_pid, ts_cc = self.parse_frame(frame)

            if ts_pid not in group:
                group[ts_pid] = {
                        'last_cc': None,
                        'seen_frames': 0,
                        'missing_frames': 0,
                        }
            pid = group[ts_pid]
            if pid['last_cc'] is None:
                pid['last_cc'] = ts_cc -1

            missing = (pid['last_cc'] + 1) - ts_cc
            if missing > 0:
                pid['missing_frames'] += missing

            pid['seen_frames'] += 1


    def print_data(self):
        for group in self.data:
            import socket
            print "Group: %s" % socket.inet_ntop(socket.AF_INET6, group)
            for pid in sorted(self.data[group]):
                pd = self.data[group][pid]
                print "  PID: %x" % pid
                print "    Seen   : %i" % pd['seen_frames']
                print "    Missing: %i" % pd['missing_frames']
                #print "    Total  : %i" % pd['seen_frames'] + pd['missing_frames']

t = tjong()

for ts, buf in pcap:
    t.process_packet(buf)
t.print_data()
