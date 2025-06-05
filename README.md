# Background
Integrated Security Solutions is a project that integrates several distinct systems, combining them into a single, powerful platform. This integrated solution makes it easier to detect, prevent, and learn attack patterns, and analyse logs centrally. This system integrates a signature-based Intrusion Detection System (IDS) developed in Python, the Snort Intrusion Prevention System (IPS), the CertiCeption honeypot, and the Graylog log management platform.


![image](https://github.com/Kasx-stha/IS/blob/main/IDS%20web.png)

# About IDS
The Intrusion Detection System (IDS) is a signature based and developed in Python. It leverages YARA rules and Regular Expression patterns to detect various attacks and forwards the corresponding logs to Snort for further action, such as dropping or rejecting the packet.

![image](https://github.com/Kasx-stha/IS/blob/main/IDS.png)

# About Snort IPS
Snort is a powerful open-source tool that functions as both an IDS and an IPS. In this project, Snort acts as the Intrusion Prevention System (IPS). It is configured to alert and drop packets based on the severity of the detected threat. It also drops packets forwarded from the Python IDS to prevent them from reaching and potentially damaging or affecting the network.

# About CertiCeption Honeypot
The CertiCeption honeypot is based on Active Directory Certificate Authority (CD). This honeypot employs a vulnerable certificate (ESC1) within the CA. It also utilizes a TameMyCerts policy module to reject any certificate signing request targeting the vulnerable template, thereby enhancing the honeypot’s security.

# About Graylog
Finally, logs from all the integrated systems are collected by the Graylog log management platform. Graylog collects logs from all components in real-time and organizes them according to their source input. This allows users to view and analyse logs centrally and in real time.

## Additional Feature
- The tool automatically generates a detailed report at the end of each day, summarizing detected attacks, associated IP addresses, and includes a bar chart visualization.
- It also offers a user-friendly web interface for easier interaction.

