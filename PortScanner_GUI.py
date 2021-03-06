import tkinter as tk
import threading
from tkinter import messagebox
import socket
import re
import queue
import ssl
import time
from os import startfile
from ruamel import yaml

# >>>>>>>>>>>>>>>>>>>>>>>>> Port Scanner <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

DEFAULT_TIMEOUT = 5
THREAD_COUNT = 256
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, " \
             "like Gecko) Chrome/83.0.4103.97 Safari/537.36 Edg/83.0.478.45"

# 构造特定端口查询时的数据
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

# 永顺终止程序
INTERRUPT = False

# 将保存的结果放在列表中，方便扫描完统一输出
result = []


# 设置发送的数据
def set_data(port):
    return REQUEST_DATA[port]


# 137/UDP 检查nbns
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


# 80/443端口获取http内容
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


# 445端口 检查开放 勘探OS
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


# 统一设置报文传输内容
def check_rep(address, port, rep):
    if port == 137:
        return lib_nbns_rep(rep=rep)

    elif port == 445:
        return lib_check_os_445(address=address, port=port)

    elif port == 6479 and 'Authentication required' not in rep:
        return '+Vulnerable+ Redis without password'

    else:
        return rep


# 统一调用高级功能 默认开启
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


# 将输入的ip做合法性检查并返回ip列表 支持掩码
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


# 将输入的ip端口格式化输出为列表 支持选择范围
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


# TCP扫描
def scan_tcp(ip_, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip_, port))
        s.close()
        return True

    except socket.error:
        return False


# UDP扫描
def scan_udp(ip_, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.sendto(b'test_msg', (ip_, port))

    try:
        # 有回传的报文 端口关闭
        rep = s.recvfrom(1024)
        return False

    except socket.error:
        return True


# 没有实现穿透 区分外部主机和本地主机扫描
# 远程扫描会主动调用以上高级方法
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


# 本地扫描会输出当前的端口的服务，实测socket内置的识别比较脑残，有些开放服务无法识别 好像MySQL的就无法识别
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


# 由该函数统一进行多线程扫描
def thread_(ip, ports):
    result.append(f'[Target IP]: {ip}')

    # 简单判断为本地ip 复杂的不想写了
    if ip.split('.')[0] == '192' and ip.split('.')[1] == '168':

        pool = [threading.Thread(target=scanner_local, args=(ip, port,)) for port in ports]

        for p in pool:
            p.start()

    # 远程主机
    else:

        pool = [threading.Thread(target=scanner_remote, args=(ip, port)) for port in ports]

        for p in pool:
            p.start()


# >>>>>>>>>>>>>>>>>>>> Graphics User Interface <<<<<<<<<<<<<<<<<<<<<<<<


class GUI(object):

    def __init__(self):

        self.on_running = False

        self.language = self.load_language()  # 加载默认语言
        self.config = self.load_config()  # 加载语言配置文件

        self.window_width = 335
        self.window_height = 206

        self.root = tk.Tk()

        self.root.geometry(f'{self.window_width}x{self.window_height}+540+250')
        self.root.title(f"{self.config['title']} v1.1.0")
        self.root.iconbitmap('.\\images\\icon.ico')
        self.root.resizable(width=False, height=False)

        self.root_initial()

        self.root.mainloop()

    def root_initial(self):

        self.menu()

        # HOSTS
        tk.Canvas(bd=2, relief='groove', width=300, height=46, ).place(x=15, y=20)
        tk.Label(text=f"{self.config['hosts']} :", font=('Microsoft YaHei', 10)).place(x=25, y=34)
        self.hosts = tk.Entry(bd=1, font=('Microsoft YaHei', 10), relief='groove', width=27)
        self.hosts.place(x=80, y=36)

        # Ports
        tk.Canvas(bd=2, relief='groove', width=300, height=46, ).place(x=15, y=80)
        tk.Label(text=f"{self.config['ports']} :", font=('Microsoft YaHei', 10)).place(x=25, y=94)
        self.ports = tk.Entry(bd=1, font=('Microsoft YaHei', 10), relief='groove', width=27)
        self.ports.place(x=80, y=96)

        # Button
        self.confirm = tk.Button(text=f"{self.config['title']}", height=1, font=('Microsoft YaHei', 18),
                                 relief='flat', command=lambda: self.thread_event(self.get_input))
        self.confirm.pack(side='bottom', ipadx=0, fill='x')

    # 按下扫描以进行获取输入并做检测，然后提交扫描
    def get_input(self):

        if self.on_running is True:

            messagebox.showinfo(f"{self.config['info']}", f"{self.config['running']}")

            return

        hosts = self.hosts.get()
        ports = self.ports.get()

        if hosts == '' or ports == '':
            messagebox.showwarning(f"{self.config['info']}", f"{self.config['input_invalid']}")

        else:

            ports = [port for port in ports.replace(' ', '').split(',')]

            if (hosts := to_ips(raw=hosts)) is None:
                messagebox.showwarning(f"{self.config['info']}", f"{self.config['input_invalid']}")
                return

            try:
                if (ports := to_ports(raw=ports)) is None:
                    messagebox.showwarning(f"{self.config['info']}", f"{self.config['input_invalid']}")

            except ValueError:
                messagebox.showwarning(f"{self.config['info']}", f"{self.config['input_invalid']}")
                return

            messagebox.showinfo(f"{self.config['info']}",
                                f"{self.config['start_1']}\n{self.config['start_2']}")

            self.on_running = True

            for ip in hosts:
                thread_(ip=ip, ports=ports)

            while True:

                if threading.active_count() == 2:

                    self.save_to_doc()

                    if messagebox.askokcancel(f"{self.config['info']}",
                                              f"{self.config['complete_1']}\n{self.config['complete_2']}"):

                        startfile('result.txt')

                    self.on_running = False

                    break

                time.sleep(0.5)

    # 程序的菜单选项
    def menu(self):

        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        lang_bar = tk.Menu(menu_bar, tearoff=0)
        lang_bar.add_command(label='English', command=self.language_switch_en_us)
        lang_bar.add_command(label='中文', command=self.language_switch_zh_cn)

        help_bar = tk.Menu(menu_bar, tearoff=0)
        help_bar.add_command(label=self.config['approve'])
        help_bar.add_command(label=self.config['feedback'])

        approve_bar = tk.Menu(help_bar, tearoff=0)
        approve_bar.add_cascade(label=self.config['approve'])

        # quit_bar = tk.Menu(menu_bar, tearoff=0)

        menu_bar.add_cascade(label=self.config['language'], menu=lang_bar)
        menu_bar.add_cascade(label=self.config['help'], menu=help_bar)
        # menu_bar.add_cascade(label=self.config['quit'], menu=quit_bar)

    # 按下菜单的英文 语言切换到英文
    def language_switch_en_us(self):

        target_config_dict = {'language': 'en-US'}

        if self.language != 'en-US':
            f_lang = open('config.yml', 'w+', encoding='utf-8')

            yaml.dump(target_config_dict, f_lang, Dumper=yaml.RoundTripDumper)

            f_lang.close()

            messagebox.showinfo(f"{self.config['info'] :}", f"{self.config['restart']}")

    # 按下菜单的中文 语言切换到中文
    def language_switch_zh_cn(self):

        target_config_dict = {'language': 'zh-CN'}

        if self.language != 'zh-CN':
            f_lang = open('config.yml', 'w+', encoding='utf-8')

            yaml.dump(target_config_dict, f_lang, Dumper=yaml.RoundTripDumper)

            f_lang.close()

            messagebox.showinfo('Info', 'Restart this program to take effect')

    # 加载语言选项文件
    def load_config(self):

        f_config = open(f'resources/{self.language}.yml', 'r', encoding='utf-8')

        config_ = yaml.load(f_config.read(), Loader=yaml.SafeLoader)

        f_config.close()

        return config_

    # 加载界面语言文件
    @staticmethod
    def load_language():

        f_lang = open('config.yml', 'r', encoding='utf-8')

        config_ = yaml.load(f_lang.read(), Loader=yaml.SafeLoader)

        f_lang.close()

        return config_['language']

    # 将结果保存到txt以查看
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

    # 用于守护线程 防止按下按钮导致界面阻塞
    @staticmethod
    def thread_event(func):

        t = threading.Thread(target=func)

        t.setDaemon(True)

        t.start()


GUI()
