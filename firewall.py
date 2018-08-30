from collections import defaultdict
from pprint import pprint


class Firewall:
    octet_max = 255

    def __init__(self, path_to_csv):
        self.rules = {
            "inbound": {
                "tcp": {},
                "udp": {},
            },
            "outbound": {
                "tcp": {},
                "udp": {},
            },
        }

        with open(path_to_csv, "r") as f:
            for line in f:
                line_split = line.split(",")
                dir = line_split[0]
                protocol = line_split[1]
                ips = Firewall.get_ips(line_split[3])
                for port in Firewall.get_ports(line_split[2]):
                    # Trying to merge dictionary
                    # https://stackoverflow.com/questions/38987/how-to-merge-two-dictionaries-in-a-single-expression
                    # if self.rules[dir][protocol][port]:
                    #     old = self.rules[dir][protocol][port]
                    #     self.rules[dir][protocol][port] = {**ips, **old}
                    self.rules[dir][protocol][port] = ips

        # pprint(self.rules)

    @staticmethod
    def get_ports(port_range):
        ports = port_range.split("-")
        if len(ports) == 1:
            return [int(ports[0])]
        else:
            low = int(ports[0])
            high = int(ports[1])
            return range(low, high+1)

    @staticmethod
    def get_ips(ip_range):
        ips = ip_range.split("-")
        if len(ips) == 1:
            octets = ips[0].split(".")
            return {
                int(octets[0]): {
                    int(octets[1]): {
                        int(octets[2]): [
                            int(octets[3]), int(octets[3])
                        ]
                    }
                }
            }
        else:
            res = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
            start_ip = ips[0].split(".")
            end_ip = ips[1].split(".")
            o1_start = int(start_ip[0])
            o1_end = int(end_ip[0])
            o2_start = int(start_ip[1])
            o2_end = int(end_ip[1])
            o3_start = int(start_ip[2])
            o3_end = int(end_ip[2])
            o4_start = int(start_ip[3])
            o4_end = int(end_ip[3])

            for i in range(o1_start, o1_end+1):
                if i < o1_end:
                    j_end = Firewall.octet_max
                else:
                    j_end = o2_end+1
                for j in range(o2_start, j_end):
                    if j < o2_end:
                        k_end = Firewall.octet_max
                    else:
                        k_end = o3_end + 1
                    for k in range(o3_start, k_end):
                        if k < o3_end:
                            end = Firewall.octet_max
                        else:
                            end = o4_end
                        res[i][j][k] = [o4_start, end]

            return res

    def accept_packet(self, dir, protocol, port, ip):
        ip_split = ip.split(".")
        o1 = int(ip_split[0])
        o2 = int(ip_split[1])
        o3 = int(ip_split[2])
        o4 = int(ip_split[3])
        try:
            o4_range = self.rules[dir][protocol][port][o1][o2][o3]
            if o4_range:
                if o4_range[0] <= o4 <= o4_range[1]:
                    return True
                else:
                    return False
            else:
                return False
        except KeyError:
            return False



fw = Firewall("rules.csv")
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
print(fw.accept_packet("inbound", "udp", 103, "192.168.2.6"))
print(fw.accept_packet("inbound", "udp", 99, "172.168.2.1"))


