import socket
import re
import threading
import queue
import ssl
from time import sleep

# for port in range(20, 1000):
#     my_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # creating new socket type of SOCK_STREAM
#     my_sock.settimeout(0.2)
#     try:
#         my_sock.connect((host, port))
#         print('>>>> Port: ', port, ' open.')
#         my_sock.close()
#     except Exception as e:
#         print(f'Port {port}. {e}')
#         pass

DEFAULT_TIMEOUT = 5
THREAD_COUNT = 256
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, " \
             "like Gecko) Chrome/83.0.4103.97 Safari/537.36 Edg/83.0.478.45"


UNIQUE_NAMES = {
    b'\x00': 'Workstation Service',
    b'\x03': 'Messenger Service',
    b'\x06': 'RAS Server Service',
    b'\x1F': 'NetDDE Service',
    b'\x20': 'Server Service',
    b'\x21': 'RAS Client Service',
    b'\xBE': 'Network Monitor Agent',
    b'\xBF': 'Network Monitor Application',
    b'\x1D': 'Master Browser',
    b'\x1B': 'Domain Master Browser',
}

GROUP_NAMES = {
    b'\x00': 'Domain Name',
    b'\x1C': 'Domain Controllers',
    b'\x1E': 'Browser Service Elections',
}

REQUEST_DATA = {
    21: b'pwd\r\n',
    80: b'GET / HTTP/1.0\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n\r\n' % USER_AGENT.encode(),
    443: b'GET / HTTP/1.0\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n\r\n' % USER_AGENT.encode(),
    6379: b'INFO\r\n',
    11211: b'stats items\r\n',
    137: b'ff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01',
}

socket.setdefaulttimeout(DEFAULT_TIMEOUT)
global_queue = queue.Queue()
lock = threading.Lock()

INTERRUPT = False

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>> EXTRA FUNCTION <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


def set_data(port):

    return REQUEST_DATA[port]


def lib_nbns_rep(rep):
    """
    UDP/137
    :param rep:
    :return:
    """

    try:
        num = ord(rep[56:57].decode())

    except Exception:
        return ''

    data = rep[57:]

    ret, group, unique, other = '', '', '', ''

    for i in range(num):

        name = data[18 * i:18 * i + 15].decode()
        flag_bit = bytes(data[18 * i + 15:18 * i + 16])

        if flag_bit == b'\x00':
            name_flag = data[18 * i + 16:18 * i + 18]

            if ord(name_flag[0:1]) >= 128:
                group = name.strip()

            else:
                unique = name

    ret = group + '\\' + unique

    return ret


def lib_get_http_info(rep):
    """
        if rep.startswith('HTTP/1.'):  # Http
            lib_get_http_info(xxxxx)
        GET first line HTTP rep and Server and Title
        """

    ret = ""
    reps = rep.split('\\r\\n')  # has been addslashes so double \...
    ret += reps[0]

    for line in reps:
        if line.startswith('Server:') or line.startswith('Location:'):
            ret += '  ' + line

    r = re.search('<title>(.*?)</title>', rep)  # get title

    if r:
        ret += ' Title: ' + r.group(1)

    return ret


def lib_check_os_445(address, port):

    try:
        payload1 = \
            b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
        payload2 = \
            b'\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00'

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)

        s.connect((address, port))
        s.send(payload1)
        s.recv(1024)

        s.send(payload2)
        data = s.recv(1024)

        length = ord(data[43:44]) + ord(data[44:45]) * 256

        data = data[47 + length:]

        if isinstance(data, str):
            return data.replace('\x00\x00', '|').replace('\x00', '')

        else:
            data = data.replace(b'\x00\x00', b'|').replace(b'\x00', b'')
            return data.decode('utf-8', errors='ignore')

    except Exception as e:
        print(e, 'smbos')
        print(address, port)
        return 'Fail to detect OS ...'


def check_rep(address, port, rep):

    if port == 137:
        return lib_nbns_rep(rep=rep)

    elif port == 445:
        return lib_check_os_445(address=address, port=port)

    elif port == 6479 and 'Authentication required' not in rep:
        return '+Vulnerable+ Redis without password'

    else:
        return rep


def extra(ip_, port):

    msg = ''
    temp_rep = ''

    if port == 137:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            data = set_data(port=port)

            s.sendto(data, (ip_, port))
            rep = s.recv(2000)

            if rep:
                rep = check_rep(address=ip_, port=port, rep=rep)
                msg += f"  {rep} "

        except socket.error:
            pass

    else:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip_, port))

        except socket.error:
            return

        try:
            msg += f"\n   {port}  "

            data = set_data(port=port)

            if port == 443:
                s = ssl.wrap_socket(s)

            s.send(data=data)
            rep = s.recv(2000)

        except socket.error:
            return

        if isinstance(rep, str):
            temp_rep = rep.replace('\n', '\\n').replace('\r', '\\r')

            temp_rep = check_rep(address=ip_, port=port, rep=temp_rep)

        else:
            temp_rep = rep.decode('utf-8', errors='ignore').replace('\n', '\\n').replace('\r', '\\r')
            temp_rep = check_rep(address=ip_, port=port, rep=temp_rep)

    msg += temp_rep

    if msg:
        lock.acquire()
        print(f"[*] {ip_} {msg}")
        lock.release()


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>> BASIC FUNCTION <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


def to_ips(raw):
    """
    :param raw: accept ip as a string
    :return: return ip_set: [ip1, ip2, ...]
    """

    try:
        return [socket.gethostbyname(raw)]

    except:

        if len(raw.split('.')) != 4:
            print('[ERROR] Raw ip input. \nexit ...')
            exit()

        if '/' in raw:
            address, mask = raw.split('/')

            if not (0 <= (mask := int(mask)) <= 24):
                print('[ERROR] Raw mask input. \nexit ...')
                exit()

            for item in address.split('.'):
                if isinstance(item, int):
                    if not (0 <= int(item) <= 255):
                        print('[ERROR] Raw mask input. \nexit ...')
                        exit()
                else:
                    print('[ERROR] Raw ip input. \nexit ...')
                    exit()

            bin_address = ''.join([(8 - len(bin(int(i))[2:])) * '0' + bin(int(i))[2:] for i in address.split('.')])

            start = bin_address[:mask] + (32 - mask) * '0'
            end = bin_address[:mask] + (32 - mask) * '1'

            bin_address = [(32 - len(bin(int(i))[2:])) * '0' + bin(i)[2:]
                           for i in range(int(start, 2), int(end, 2) + 1)]
            dec_address = ['.'.join([str(int(bin_address_[8 * i:8 * (i + 1)], 2))
                                     for i in range(0, 4)]) for bin_address_ in bin_address]

            return dec_address

        elif '-' in raw:
            address, end = raw.split('-')

            start = int(address.split('.')[3])
            end = int(end)

            prefix = '.'.join(address.split('.')[:-1])

            address = [prefix + '.' + str(i) for i in range(start, end + 1)]

            return address

        else:
            return [raw]


def to_ports(raw):
    ports = []

    for item in raw:

        if '-' not in item:
            if 0 <= (item := int(item)) <= 255:
                ports.append(item)

            else:
                print('[ERROR] Raw ports input')
                exit()

        else:
            start, end = item.split('-')

            if 0 <= (start := int(start)) < 255 and 0 <= (end := int(end)) <= 255:
                ports += range(start, end + 1)

            else:
                print('[ERROR] Raw ports input')
                exit()

    return list(set(ports))


def scan_tcp(ip, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip, port))
        s.close()
        return True

    except socket.error:
        return False


def scan_udp(ip, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.sendto(b'test_msg', (ip, port))

    try:
        rep = s.recvfrom(1024)
        return True

    except socket.error:
        return False


def scanner_remote(ip, port, flag):

    if INTERRUPT is True:

        return

    elif flag is True and port in REQUEST_DATA:

        extra(ip_=ip, port=port)

    elif scan_tcp(ip=ip, port=port):

        print(f"[+] {ip} %3d TCP OPEN" % port)

    elif scan_udp(ip=ip, port=port):

        print(f"[+] {ip} %3d UDP OPEN" % port)


def scanner_local(ip_, port):

    port_type = 'tcp'
    port_type1 = 'udp'
    
    try:
        print(f"[+]  OPEN  {ip_}  %3s  {port_type}  >  {socket.getservbyport(port, port_type)}" % port)

    except:
        try:
            print(f"[+]  OPEN  {ip_}  %3s  {port_type1}  >  {socket.getservbyport(port, port_type1)}" % port)

        except:
            pass


def thread_(ip, ports, flag=False):

    if ip.split('.')[0] == '192':

        pool = [threading.Thread(target=scanner_local, args=(ip, port, )) for port in ports]

        for p in pool:
            p.start()

    else:

        pool = [threading.Thread(target=scanner_remote, args=(ip, port, flag)) for port in ports]

        for p in pool:
            p.start()


if __name__ == '__main__':
    # host = 'scanme.nmap.org'
    # host = '220.181.38.148'
    host = '192.168.2.105'

    ips = to_ips(raw=host)
    ports_ = to_ports(raw=['0-255'])

    for ip in ips:

        thread_(ip=ip, ports=ports_)
