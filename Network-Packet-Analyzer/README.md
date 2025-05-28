**Python Network Sniffer**

**Overview**
A network sniffer that captures and analyzes network packets. Built as a learning project to understand how network data flows and how packet headers are structured.

**Features**
- Capture and display Ethernet, IPv4, TCP, UDP, and ICMP packets.

**Log captured packets to a file.**
- Clean and organized data output for better readability.

**Usage Instructions**

Run the program as root (required for raw socket access):
- sudo python3 main.py

**The program will continuously sniff packets.**
- Press Ctrl+C to stop the sniffer.

**Log File Example**

![Screenshot 2025-05-14 221323](https://github.com/user-attachments/assets/9ff0f026-8b41-47a0-95c6-71ea0cf76d3d)


**Security Considerations**
- Running a network sniffer without authorization is illegal. Use responsibly and only on networks you own or have permission to monitor.
