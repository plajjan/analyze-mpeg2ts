#!/usr/bin/python

import dpkt
import logging
import socket


class MPEG2TS(dpkt.Packet):
    __hdr__ = (
            ('syncb', 'B', 0),
            ('stuff', 'H', 0),
            ('stuff2', 'B', 0)
            )

class AnalyzeM2TS:
    def __init__(self):
        self.logger = logging.getLogger()
        self.data = {}

        # the total number of packets we have seen in the pcap
        self.total_packets = 0
        # number of packets that are IPv6 & UDP
        self.ipv6udp_packets = 0
        # number of "short" packets, ie with less than 188 bytes of data
        self.short_packets = 0
        # number of processed packets
        self.processed_packets = 0

        self.process_n_frames = None

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

        return ts_pid, ts_afc, ts_cc



    def process_packet(self, packet):
        self.total_packets += 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP6:
            return
        ip = eth.data

        if ip.nxt != dpkt.ip.IP_PROTO_UDP:
            return
        udp = ip.data
        data = udp.data

        self.ipv6udp_packets += 1
        if len(data) < 188:
            self.short_packets += 1
            return
        self.processed_packets += 1
        group_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)

        if group_ip not in self.data:
            self.logger.debug("New group: " + group_ip)
            self.data[group_ip] = {}
        group = self.data[group_ip]

        FRAME_LENGTH = 188
        i = 0
        self.logger.debug("Packet payload length: " + str(len(data)))
        while i < len(data) and i + FRAME_LENGTH <= len(data):

            frame = data[i:i+FRAME_LENGTH]
            i += FRAME_LENGTH

            ts_pid, ts_afc, ts_cc = self.parse_frame(frame)
            #self.logger.debug("PID: 0x%x AFC: %s CC: %d" % (ts_pid, ts_afc, ts_cc))
            self.logger.debug("Processing MPEG2TS frame at byte %d - PID: 0x%x CC: %d" % (
                i - FRAME_LENGTH, ts_pid, ts_cc))

            if ts_pid not in group:
                self.logger.debug("New TS PID: %x - init CC to: %d" % (ts_pid, ts_cc))
                group[ts_pid] = {
                        'last_cc': ts_cc,
                        'seen_frames': 0,
                        'missing_frames': 0,
                        }
                continue

            pid = group[ts_pid]
            pid['seen_frames'] += 1
            if ts_pid == 0x1fff or ts_afc == 0x2:
                continue

            missing = ((pid['last_cc']+1) % 16) - ts_cc
            if missing > 0:
                self.logger.error("AFC %x" % (ts_afc))
                self.logger.error("Missing %d frame for PID 0x%x expected %d got %d" % (
                    missing, ts_pid, (pid['last_cc'] % 16) + 1, ts_cc))
                pid['missing_frames'] += missing

            pid['last_cc'] += 1



    def print_data(self):
        print "Total packets:", self.total_packets
        print "IPv6 UDP packets:", self.ipv6udp_packets
        print "Short packets:", self.short_packets
        print "Processed packets:", self.processed_packets
        for group_ip in self.data:
            print "Group: %s" % group_ip
            for pid in sorted(self.data[group_ip]):
                pd = self.data[group_ip][pid]
                print "  PID: %x" % pid
                print "    Seen   : %i" % pd['seen_frames']
                print "    Missing: %i" % pd['missing_frames']
                #print "    Total  : %i" % pd['seen_frames'] + pd['missing_frames']

if __name__ == '__main__':
    logger = logging.getLogger()
    log_stream = logging.StreamHandler()
    log_stream.setFormatter(logging.Formatter("%(asctime)s: %(levelname)-8s %(message)s"))
    logger.addHandler(log_stream)

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+', help='input file')
    parser.add_argument('--process-n', type=int, help='process a maximum of N packets')
    parser.add_argument('--debug', action='store_true', help='debug')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    for filename in args.files:
        print "Processing file:", filename
        m = AnalyzeM2TS()

        f = file(filename, 'rb')
        pcap = dpkt.pcap.Reader(f)

        n_packet = 0
        for ts, buf in pcap:
            m.process_packet(buf)
            n_packet += 1
            if args.process_n and n_packet > args.process_n:
                break
        m.print_data()
