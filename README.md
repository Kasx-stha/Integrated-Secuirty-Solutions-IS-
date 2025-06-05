# Integrated Security Solutions (IS)
Integrated Security Solutions is a project that integrates several distinct systems, combining them
into a single, powerful platform. This integrated solution makes it easier to detect, prevent, and
learn attack patterns, and analyse logs centrally. This system integrates a signature-based
Intrusion Detection System (IDS) developed in Python, the Snort Intrusion Prevention System
(IPS), the CertiCeption honeypot, and the Graylog log management platform.

The Intrusion Detection System (IDS) is a signature based and developed in Python. It leverages
YARA rules and Regular Expression patterns to detect various attacks and forwards the
corresponding logs to Snort for further action, such as dropping or rejecting the packet.

Snort is a powerful open-source tool that functions as both an IDS and an IPS. In this project, Snort
acts as the Intrusion Prevention System (IPS). It is configured to alert and drop packets based on
the severity of the detected threat. It also drops packets forwarded from the Python IDS to prevent
them from reaching and potentially damaging or affecting the network.

Snort is a powerful open-source tool which is also an IDS and also an IPS. In this project Snort
acts as an Intrusion Prevention System. It is configured to alert, drop packet based on the severity
of the maliciousness it contains. It also drops the packet that is forwarded from the IDS to prevent
it from reaching the network and destroying or effecting the network.

The CertiCeption honeypot is based on Active Directory Certificate Authority (CD). This
honeypot employs a vulnerable certificate (ESC1) within the CA. It also utilizes a TameMyCerts
policy module to reject any certificate signing request targeting the vulnerable template, thereby
enhancing the honeypot’s security.

Finally, logs from all the integrated systems are collected by the Graylog log management
platform. Graylog collects logs from all components in real-time and organizes them according to
their source input. This allows users to view and analyse logs centrally and in real time.
