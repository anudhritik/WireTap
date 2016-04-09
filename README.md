# WireTap
Computer Networks Course Project - Indiana University Bloomington
The main functionality of this assignment Wiretap is to analyze the packets being transmitted. This
project takes a file as an input which contains the tcpdump data and presents as an output the Summary
which consists information about the number of packets, the minimum and maximum packet size, and
the average packet size. The output also displays the various layers header formats captured including
that of the Link Layer, Network Layer and Transport Layer.
In the Link layer, it displays unique Ethernet source and destination addresses in Hex format also
specifying the number of packets each address contains.
Network Layer, displays the unique Network layer protocols and how many number of packets each
protocol contains. Also, it displays the unique source IP and Destination IP addresses and gives the
unique ARP participants
Transport Layer, it displays the Transport layer protocols and how many packets each protocol contains.
It displays the unique source and destination TCP port specifying the number of packets for every
unique port, also tells about the count of packets holding the TCP flags, options. It displays the source
and destination UDP port specifying the number of packets for each unique port. Also gives the number
of packets that contain ICMP types.
