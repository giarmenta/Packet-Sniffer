# Packet-Sniffer
C file that sniffs packets and passwords from Telnet.

Introduction:

This is a sniffer program in C using PCAP to sniff packets with the capabilities of obtaining passwords from somebody using telnet. It includes filtering capabilities for desired packet sniffing and includes the capability for the user to input a port range.

Also includes Sample.py for Task 1 assignments. Uses, scary import to sniff packets and provide packet info to the user. 

Requirement:

To run the program, one must have gcc installed along with PCAP library. Compiling options must include the following: gcc sniff.c -lpcap and when running one must provide superuser or root privileges like the following: sudo ./a.out.

To run the python program, one must have python3 installed along with scapy. 

Instructions:

To run to test Task-2(b)i. On line 136 of the mySniffer.c code, change char filter_exp[] =  "imp and host ###.###.###.### and dst ###.###.###.###; and comment out lines 143 to 145. The # represent any number of your choice for the IP address. An IP address is shown in the comments for line 136 within the code. Lines 143 to 145 are for the user's ability to enter a port range.

To run to test Task-2(b)ii. On line 136 of the mySniffer.c code, change char filter_exp[] = "tcp and ";. Also, make sure lines 143 and 143 are not commented out. MUST have a space after and in the filter_exp[] just like it is shown above. There is the code commented out in line 136. To enter the port range you can select any number from 0 to 65535 just like in the example that will print out when the system asks you for the port range. The port range is entered like follows: 0-5555 and just hit enter, no spaces are necessary. 

To run to test Task-2(c). On line 136 of the mySniffer.c code, change char filter_exp[] = "tcp and port 23"; and comment out lines 143 to 145. You can also add the desired IP address to to sniff on after the port number. Once the user of the device being sniffed on starts entering the password, you will be able to see it character by character. 

The python program must also be ran with root privileges to run. To run Task-1(b)i. remove the current option in the filter and replace it with 'icmp' and run. Run as is for Task-1(b)ii. 

Done by: Gerardo Armenta
