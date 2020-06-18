import tkinter as tk
import threading
from tkinter import messagebox
import socket
import re
import queue
import ssl
import time
from os import startfile

# >>>>>>>>>>>>>>>>>>>>>>>>> Port Scanner <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

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

result = []


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

    except:
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
        result.append(f"[*] {ip_} {msg}")
        lock.release()


def to_ips(raw):
    """
    :param raw: accept ip as a string
    :return: return ip_set: [ip1, ip2, ...]
    """

    try:
        return [socket.gethostbyname(raw)]

    except:

        if len(raw.split('.')) != 4:
            return None

        if '/' in raw:
            address, mask = raw.split('/')

            if not (0 <= (mask := int(mask)) <= 24):
                return None

            for item in address.split('.'):
                if isinstance(item, int):
                    if not (0 <= int(item) <= 255):
                        return None
                else:
                    return None

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
            if 0 <= (item := int(item)) <= 25565:
                ports.append(item)

            else:
                return None

        else:
            start, end = item.split('-')

            if 0 <= (start := int(start)) < 25565 and 0 <= (end := int(end)) <= 25565:
                ports += range(min(start, end), max(start, end) + 1)

            else:
                return None

    return list(set(ports))


def scan_tcp(ip_, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip_, port))
        s.close()
        return True

    except socket.error:
        return False


def scan_udp(ip_, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.sendto(b'test_msg', (ip_, port))

    try:
        rep = s.recvfrom(1024)
        return True

    except socket.error:
        return False


def scanner_remote(ip_, port):

    if INTERRUPT is True:
        return

    elif port in REQUEST_DATA:

        extra(ip_=ip_, port=port)

    elif scan_tcp(ip_=ip_, port=port):

        res = f"[+]  OPEN  {ip_}  %3d TCP" % port
        result.append(res)

    elif scan_udp(ip_=ip_, port=port):

        res = f"[+] {ip_} %3d UDP OPEN  UDP" % port
        result.append(res)


def scanner_local(ip_, port):

    if INTERRUPT is True:
        return

    port_type = 'tcp'
    port_type1 = 'udp'

    try:
        res = f"[+]  OPEN  {ip_}  %3s  {port_type}  >  {socket.getservbyport(port, port_type)}" % port
        result.append(res)

    except:
        try:
            res = f"[+]  OPEN  {ip_}  %3s  {port_type1}  >  {socket.getservbyport(port, port_type1)}" % port
            result.append(res)

        except:
            pass


def thread_(ip, ports):

    result.append(f'[Target IP]: {ip}')

    if ip.split('.')[0] == '192' and ip.split('.')[1] == '168':

        pool = [threading.Thread(target=scanner_local, args=(ip, port,)) for port in ports]

        for p in pool:

            p.start()

    else:

        pool = [threading.Thread(target=scanner_remote, args=(ip, port)) for port in ports]

        for p in pool:
            p.start()


# >>>>>>>>>>>>>>>>>>>> Graphics User Interface <<<<<<<<<<<<<<<<<<<<<<<<


class GUI(object):

    def __init__(self):

        self.on_running = False
        self.window_width = 335
        self.window_height = 206

        self.root = tk.Tk()

        self.root.geometry(f'{self.window_width}x{self.window_height}+540+250')
        self.root.title('Port Scanner v1.0 Beta')
        self.root.iconbitmap('.\\images\\icon.ico')
        self.root.resizable(width=False, height=False)

        self.root_initial()

        self.root.mainloop()

    def root_initial(self):

        self.menu()

        # HOSTS
        tk.Canvas(bd=2, relief='groove', width=300, height=46, ).place(x=15, y=20)
        tk.Label(text='Hosts :', font=('Microsoft YaHei', 10)).place(x=25, y=34)
        self.hosts = tk.Entry(bd=1, font=('Microsoft YaHei', 10), relief='groove', width=27)
        self.hosts.place(x=80, y=36)

        # Ports
        tk.Canvas(bd=2, relief='groove', width=300, height=46, ).place(x=15, y=80)
        tk.Label(text='Ports :', font=('Microsoft YaHei', 10)).place(x=25, y=94)
        self.ports = tk.Entry(bd=1, font=('Microsoft YaHei', 10), relief='groove', width=27)
        self.ports.place(x=80, y=96)

        # Button
        self.confirm = tk.Button(text='Port Scanner', height=1, font=('Microsoft YaHei', 18),
                                 relief='flat', command=lambda: self.thread_event(self.get_input))
        self.confirm.pack(side='bottom', ipadx=0, fill='x')

    def get_input(self):

        hosts = self.hosts.get()
        ports = self.ports.get()

        if hosts == '' or ports == '':
            messagebox.showwarning('Info', 'Void input')

        else:

            ports = [port for port in ports.replace(' ', '').split(',')]

            if (hosts := to_ips(raw=hosts)) is None:
                messagebox.showwarning('Info', 'Invalid Hosts')
                return

            try:
                if (ports := to_ports(raw=ports)) is None:
                    messagebox.showwarning('Info', 'Invalid Ports')

            except ValueError:
                messagebox.showwarning('Info', 'Invalid Ports')
                return

            messagebox.showinfo('Info', 'Start Scanning...\n'
                                        'Please wait a second')

            for ip in hosts:
                thread_(ip=ip, ports=ports)

            while True:

                if threading.active_count() == 2:

                    self.save_to_doc()

                    if messagebox.askokcancel('Info', 'Scanning Completed.\n'
                                                   'Open it now?'):
                        startfile('result.txt')

                    break

                time.sleep(0.5)

    def menu(self):

        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        lang_bar = tk.Menu(menu_bar, tearoff=0)
        lang_bar.add_command(label='English')
        lang_bar.add_command(label='Chinese')

        help_bar = tk.Menu(menu_bar, tearoff=0)
        help_bar.add_command(label='Approve')
        help_bar.add_command(label='Github')

        quit_bar = tk.Menu(menu_bar, tearoff=0)

        menu_bar.add_cascade(label='Language', menu=lang_bar)
        menu_bar.add_cascade(label='Help', menu=help_bar)
        menu_bar.add_cascade(label='Quit', menu=quit_bar)

    @staticmethod
    def save_to_doc():

        f = open('result.txt', 'w+', encoding='utf-8')

        for item in result:
            f.write(item + '\n')

        f.write('\n')

        f.close()

        f_old = open('result_history.txt', 'a+', encoding='utf-8')

        for item in result:
            f_old.write(item + '\n')

        f_old.write('\n')

        f_old.close()

    @staticmethod
    def thread_event(func):

        t = threading.Thread(target=func)

        t.setDaemon(True)

        t.start()


GUI()
