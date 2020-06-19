# Port Scanner for Windows (Python)

> Already test based on environment: python3.7,  Windows 10

## 🚀 Usage

> ```bash
> python .\PortScanner_GUI.py [target_ip] [-args|-args]  # Run with CLI
> ```

>```bash
>python .\PortScanner-CLI.py  # Enter gui mode, data will be saved in ./result.txt
>```

> ```
> args:
>   ├─ ip: Input ip. (acquired)
>   ├─ -p: Port.
>   └─ -h: Get more help info.
>   ```

## 🚀 ISSUE

| Function                     | Status | Remark |
| ---------------------------- | :----: | :----: |
| Port Scanning basic function |   ✔    |        |
| CLI basic function | ✔ | Usage |
| Add multi threads         | ✔ |        |
| Graphic User Interface     | ✔ |        |
| Final Combine | ✔ |        |


## 🚀 Requirements 
> ### Using Socket communication mechanism to realize a multi-threaded port scanner

---

> #### 🔔Requirement:
> 
> - 用户界面：用户可以输入IP地址或IP地址段；输入端口号或端口号范围；列表显示主机名、开放的端口及开放端口上相应的服务名称
> - 端口的有效范围是1~65535，在该范围内使用多线程机制循环创建客户端套接字对象，对某一地址（段）的主机端口进行扫描，若套接字没有发生异常，说明该端口打开并提供服务，返回该开放端口的类型（如UDP端口还是TCP端口）。
> - 采用  ~~Java~~ 网络编程包java.io中提供的编程接口实现。



## 🚀 Changelog

> - Alpha    0.0.1	:  Support TCP-connect scanning and UDP scanning.
> - Alpha    0.0.4	:  Run program in CLI with parameter support.
> - Beta      0.0.7	:  Add GUI.
> - Beta      0.1.3    :  Get more data when in special port. ( example: port:173: Get data based on [UBNS ](https://wiki.wireshark.org/NetBIOS/NBNS) )
> - Beta      0.2.1    : Get more data in special port. ( Add port 80/443 to get HTTP/1.0 header)
> - Beta      0.3.1    : Get more data in special port. ( Add port 445 to detect OS. [[SMB](https://en.wikipedia.org/wiki/Server_Message_Block)])
> - Beta      0.4.3    : Support check WIN10 bugs: MS_17_010, check if it's attackable.
> - Beta      0.4.4    : Remove function: Check MS_17_010. It's unstable and crush the program in some cases.
> - Released     1.0.0    :  Adjust program's structure.
> - Released     1.0.1    :  Improve stability and performance.
> - Released     1.1.0    :  Support switch language [zh-hans / en-us]