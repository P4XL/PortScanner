# Port Scanner for Windows (Python)

> Already test based on environment: python3.7,  Windows 10

## 🚀 Usage

> ```python
> python .\PortScanner_CLI.py [target_ip] [-args|-args]  # Run with CLI
> ```

> ```
> args:
>   ├─ -c: Custom port range. (When parameter is 0, scanning full port)
>   ├─ -p: Select one port. (Support more parameters '-p')
>   ├─ -o: Output Verbose data. 
>   ├─ -e: Export mode. (more scanning method support. To be finish )
>   ├─ -g: Graphic User Interface mode.
>   ├─ -h: Get more help info.
>   └─ -v: Version.
> ```

## 🚀 ISSUE

| Function                     | Status | Remark |
| ---------------------------- | :----: | :----: |
| Port Scanning basic function |   ✔    |        |
| CLI basic function | ✔ | Usage |
| Add multi threads         | ✔ |        |
| Graphic User Interface     |  |        |
| Final Combine | - |        |


## 🚀 Requirements 
> ### Using Socket communication mechanism to realize a multi-threaded port scanner

---

> #### 🔔Requirement:
> 
> - 用户界面：用户可以输入IP地址或IP地址段；输入端口号或端口号范围；列表显示主机名、开放的端口及开放端口上相应的服务名称
> - 端口的有效范围是1~65535，在该范围内使用多线程机制循环创建客户端套接字对象，对某一地址（段）的主机端口进行扫描，若套接字没有发生异常，说明该端口打开并提供服务，返回该开放端口的类型（如UDP端口还是TCP端口）。
> - 采用  ~~Java~~ 网络编程包java.io中提供的编程接口实现。



## 🚀 Changelog

> - Alpha 0.1	:  Support TCP-connect scanning and UDP scanning.
> - Alpha 0.2	:  Run program in CLI with parameter support.
> - Alpha 0.3	:  