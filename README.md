# Network Packet Analyzer

This tool is a Python-based network packet analyzer developed using the Scapy library, designed to capture and analyze network traffic in real-time. It focuses on IP-based packets and provides insights into network protocols like TCP, UDP, and ICMP.

### **Key Features** 📋:  
1. **Real-Time Packet Capture** 🕵️‍♂️:  
   - Monitors live network traffic and captures IP-based packets.  

2. **Protocol Identification** 🔍:  
   - Recognizes key protocols: **TCP**, **UDP**, and **ICMP**.  

3. **Detailed Packet Insights** 📊:  
   - Displays:  
     - **Source and Destination IPs**  
     - **Protocol Type**  
     - **Payload Data** for TCP/UDP packets (if available).  

---

### **How It Works** ⚙️:  
1. **Packet Sniffing**:  
   - Uses the **Scapy library** to sniff real-time network traffic.  
   - Filters traffic to focus on IP-based packets.  

2. **Packet Analysis**:  
   - For each captured packet:  
     - Extracts the **source and destination IP addresses**.  
     - Identifies the **protocol type** (e.g., TCP, UDP, ICMP).  
     - Retrieves **payload data** for TCP/UDP packets, if available.  

3. **Customizable Interface**:  
   - Allows specifying the network interface (e.g., `eth0`, `wlan0`) for targeted packet capture.  

---

### **Technologies Used** 🛠️:  
- **Python** 🐍: For building the packet analyzer.  
- **Scapy** 🛡️: A powerful Python library for packet sniffing and manipulation.  

---

This tool is a lightweight yet powerful solution for **network traffic analysis**, making it useful for **network security research** and understanding real-time traffic patterns. Looking forward to applying these concepts in more advanced projects! 🚀

### **Code**  

Here is the Python code for the Network Packet Analyzer:
```
