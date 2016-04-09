
/*
 * References:
 	http://www.binarytides.com/code-packet-sniffer-c-winpcap/
 	http://www.codecogs.com/library/computing/c/time.h/tzset.php (for timezoen info)
 */

// standard libraries
#include <iostream>
#include <cstdlib>
#include <iomanip>

using namespace std;

#include "wt_lib.h"

// include all packet capture helper libraries
#include "/usr/include/netinet/ip.h"
#include "/usr/include/netinet/tcp.h"
#include "/usr/include/netinet/udp.h"
#include "/usr/include/netinet/ip_icmp.h"
#include "/usr/include/arpa/inet.h"
#include "/usr/include/pcap/bpf.h"
#include "/usr/include/linux/if_ether.h"
#include <sys/time.h>

/******************** declare global variables *************************/
//---------- for Packet capture summary  ---------------------------------------------
static time_t pkt_start_time;	// to grab UNIX epoch time in seconds from "struct timeval" for first packet
static char timewithzone_str[64];	// time with local timezone to be written to this char array
static time_t pkt_end_time;	// to grab UNIX epoch time in seconds from "struct timeval" for last packet
static int pkt_count;	// to count total number of packets being scanned
static unsigned int min_pktlen;	// store minimum packet length
static unsigned int max_pktlen;	// store maximum packet length
static int pktlen_sum;	// sum of lengths of all packets
//---------- ethernet address maps ---------------------------------------------------
map<std::string, int> src_ethaddr_map;	// "ordered map" to store source ethernet addresses
map<std::string, int> dst_ethaddr_map;	// "ordered map" to store destination ethernet addresses
//-------------------------------------------------------------------------------------
map<std::string, int>::iterator itr;	// iterator to iterate over elemnents in a map
//---------- IP address maps ---------------------------------------------------
map<std::string, int> src_ipaddr_map;	// to store source IP addresses
map<std::string, int> dst_ipaddr_map;	// to store destination IP addresses
//-----------ARP header --------------------------------------------------------------
typedef struct {
	unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
	unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];		/* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];		/* Target IP address.  */
} arp_hdr_t;

map<std::string, int> arp_map;	// to hold ARP packet info

map<std::string, int> mapofothers;	// to store other than IPv4 or ARP
//-----------TCP header --------------------------------------------------------------

map<std::string, int> tcp_sportmap;	// to hold tcp source ports
map<std::string, int> tcp_dportmap;	// to hold tcp destination ports

map<std::string, int> tcp_flagsmap;	// to store tcp flags (ACK, FIN, etc.) counts

/* for type 2 */
map<std::string, int> mapof2;	// to store protocol 2 type entries

/* for type UDP */
map<std::string, int> udp_sportmap;	// to hold udp source ports
map<std::string, int> udp_dportmap;	// to hold udp destination ports

/* for type ICMP */
map<std::string, int> icmp_typemap;	// to hold ICMP types if any
map<std::string, int> icmp_codemap;	// to hold ICMP codes if any
/******************** end global variables declaration *************************/

int main(int argc, char *argv[]) {

	PacketParser *wt_args = NULL;	// assign to NULL to avoid "uninitialization" warning
	wt_args->parse_args(argc, argv, &wt_args);	// parse command-line arguments

	char errbuf[PCAP_ERRBUF_SIZE];	// stores error text when pcap_open_offline() fails
	init_tcp_flagsmap(tcp_flagsmap);	// initialize map to set all TCP flag counts to 0 initially

	pcap_t *pcp = pcap_open_offline(wt_args->get_filename(), errbuf);	// open given packet capture file
	if (!pcp) {	// check if packet capture file was unsuccessful just in case
		cerr << "Could not open packet capture file: " << wt_args->get_filename() << endl;
		usage(stderr);
		exit(1);
	}

	if (pcap_datalink(pcp) != DLT_EN10MB) {	// capture ethernet device packets and none other
		fprintf(stderr, "Ethernet device packets not found. Program proceeding to termination.\n");
		exit(1);
	} else {

		pcap_loop(pcp, -1, pcap_callback, NULL);	// loop through each packet until all packets are parsed
		cout << endl << setfill('*') << setw(80) << "\n\n";
		cout << "=============== Packet capture summary ===============" << endl << endl;
		
		cout << "Capture start date: \t\t" << timewithzone_str << endl;
		cout << "Capture duration: \t\t" << (pkt_end_time - pkt_start_time) << " seconds" << endl;
		cout << "Packets in capture: \t\t" << pkt_count << endl;

		cout << "Minimum packet size: \t\t" << min_pktlen << endl;
		cout << "Maximum packet size: \t\t" << max_pktlen << endl;
		cout << "Average packet size: \t\t";
		fprintf( stdout, "%.2f", (pktlen_sum / (float) pkt_count) );
		cout << endl << endl;
		
		// first, get set to display link layer content in packet
		cout << "=============== Link layer ===============" << endl << endl;
		cout << "------ Source ethernet addresses ------" << endl << endl;
		print_map(src_ethaddr_map);
		cout << endl;
		cout << "------ Destination ethernet addresses ------" << endl << endl;
		print_map(dst_ethaddr_map);

		// now display network layer content in packet
		cout << "\n" << "=============== Network layer ===============" << endl << endl;
		cout << "------ Network layer protocols ------" << endl << endl;

		// iterator through map that contains other lesser known protocols
		for (itr = mapofothers.begin(); itr != mapofothers.end(); itr++) {
			cout << itr->first << "\t\t" << itr->second << endl;
		}
		
		cout << "ARP" << "\t\t\t" << count_unique(arp_map) << endl;
		cout << "IP" << "\t\t\t" << count_unique(src_ipaddr_map) << endl;
		cout << endl;

		cout << "------ Source IP addresses ------" << endl << endl;
		print_map(src_ipaddr_map);
		cout << endl;
		cout << "------ Destination IP addresses ------" << endl << endl;
		print_map(dst_ipaddr_map);
		cout << endl;
		cout << "------ Unique ARP participants ------" << endl << endl;
		print_map(arp_map);
		cout << endl;
		cout << "\n" << "=============== Transport layer ===============" << endl << endl;
		cout << "------ Transport layer protocols ------" << endl << endl;
		
		cout << "2" << "\t\t" << count_unique(mapof2) << endl;
		cout << "ICMP" << "\t\t" << count_unique(icmp_typemap) << endl;	/* print counts */
		cout << "TCP" << "\t\t" << count_unique(tcp_sportmap) << endl;
		cout << "UDP" << "\t\t" << count_unique(udp_sportmap) << endl;
		cout << endl;

		cout << "------ Transport layer: TCP ------" << endl << endl;
		cout << "------ Source TCP ports ------" << endl << endl;
		print_map(tcp_sportmap);
		cout << endl;
		cout << "------ Destination TCP ports ------" << endl << endl;
		print_map(tcp_dportmap);
		cout << endl;
		cout << "------ TCP flags ------" << endl << endl;
		print_map(tcp_flagsmap);
		cout << endl;
		cout << "------ TCP options ------" << endl << endl;
		cout << "------ Transport layer: UDP ------" << endl << endl;
		cout << "------ Source UDP ports ------" << endl << endl;
		print_map(udp_sportmap);
		cout << endl;
		cout << "------ Destination UDP ports ------" << endl << endl;
		print_map(udp_dportmap);
		cout << endl;
		cout << "------ Transport layer: ICMP ------" << endl << endl;
		cout << "------ ICMP types ------" << endl << endl;
		print_map(icmp_typemap);
		cout << endl;
		cout << "------ ICMP codes ------" << endl << endl;
		print_map(icmp_codemap);
		cout << endl;
		cout << setfill('*') << setw(80) << "\n\n";

		pcap_close(pcp);	// close packet capture file
	}

	// release object memory
	delete wt_args;

	return 0;
}

/*
 * this function is the callback routine referenced in pcap_loop();
 * the function loops through each packet's content to scan out relevant information.
 *
 * pcap_callback() -> void
 */
void pcap_callback(u_char *user, const struct pcap_pkthdr* phdr, const u_char *packet) {
	
	pkt_count++;	// increment count of packets each time the callback is called for a packet

	struct tm *localtm;	// structure containing a calender date and time broken down to its components like hour, day of the month, etc.
	char timebuf[64];	// char array buffer
	memset(timebuf, 0x00, sizeof timebuf);	// zero-out buffer inititally

	if (pkt_count == 1) {	// first packet's arrival time

		memset(timewithzone_str, 0x00, sizeof timewithzone_str);	// zero-out buffer before use
		pkt_start_time = phdr->ts.tv_sec;	// get UNIX epoch time in seconds
		localtm = localtime(&pkt_start_time);	// fill in structure "struct tm"
		tzset();	// set timezone to local timezone; initializes the tzname variable with best approximation of local wall clock time
		strftime(timebuf, sizeof timebuf, "%Y-%m-%d %H:%M:%S", localtm);	// to desired time format stored in char array buffer
		snprintf(timewithzone_str, sizeof timewithzone_str, "%s %s", timebuf, tzname[1]);	// add timezone info
	}

	/* keep a tab on minimum packet size */
	if (min_pktlen == 0)	// first packet being scanned
		min_pktlen = phdr->len;
	else if (phdr->len < min_pktlen)
		min_pktlen = phdr->len;	// set new minimum if a packet size with lesser size is encountered

	/* likewise, track maximum packet size */
	if (max_pktlen == 0)	// first packet
		max_pktlen = phdr->len;
	else if (phdr->len > max_pktlen)
		max_pktlen = phdr->len;

	/* keep track of average packet size */
	pktlen_sum += phdr->len;

	/* keep track of the last packet's capture time */
	pkt_end_time = phdr->ts.tv_sec;

	/********* parse header types *********/
	parse_hdrs(packet);

}

/*
 * parse_hdrs() -> void
 * 		parses the different header-types in the packet
 * function argument 'const u_char *pkt' is a pointer to the start of the packet header (ETH)
 */
void parse_hdrs(const u_char *pkt) {

	char buf[40];	// char array buffer to hold strings
	memset(buf, 0x00, sizeof(buf));	// zero-out buffer initially

	//-------------------- ETH header parsing ------------------------------------------

	struct ethhdr *eth_hdr = (struct ethhdr *) pkt;	// cast packet to ethernet header type
	
	/* get source Ethernet address as a string */
	snprintf(buf, 40, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2], eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
	string eth_address_src(buf);	// convert char array to string

	/* now, get destination Ethernet address as a string */
	memset(buf, 0x00, sizeof(buf));	// flush-out buffer for reuse
	snprintf(buf, 40, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2], eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
	string eth_address_dst(buf);

	/* insert source eth addr & destination eth addr in their respective "ordered map"s */
	mapping_elems(eth_address_src, src_ethaddr_map);
	mapping_elems(eth_address_dst, dst_ethaddr_map);
		
	//-------------------- end ETH header parsing -------------------------------------

	struct iphdr *ip_hdr = (struct iphdr *) (pkt + ETH_HLEN);	// get a pointer to IP header type
	arp_hdr_t *arp_hdr = (arp_hdr_t *) ip_hdr;	// cast iphdr to arp header type

	if (ntohs(eth_hdr->h_proto) == ETH_P_IP) {	// only account for IPv4 packets
		string src_ipaddr( inet_ntoa( *(struct in_addr *) &ip_hdr->saddr ) );	// convert u_int32_t to dotted IP addr string
		mapping_elems(src_ipaddr, src_ipaddr_map);	// have a unique count of src IP addr in a map
		string dst_ipaddr( inet_ntoa( *(struct in_addr *) &ip_hdr->daddr) );	// destination IP addr like done for src IP addr
		mapping_elems(dst_ipaddr, dst_ipaddr_map);

		struct tcphdr *tcp_hdr = (struct tcphdr *) (pkt + ETH_HLEN + sizeof(struct iphdr));	// get pointer to TCP header in packet
		struct udphdr *udp_hdr = (struct udphdr *) tcp_hdr;	// cast to UDP type
		struct icmphdr *icmp_hdr = (struct icmphdr *) tcp_hdr;	// cast to ICMP type

		string str2("2");	// for protocol type: "2"

		// parse differently for different protocols
		switch(ip_hdr->protocol) {
			case 2:	// for type: "2"
				mapping_elems(str2, mapof2);
				break;

			case IPPROTO_TCP:	// TCP type
				memset(buf, 0x00, sizeof(buf));
				snprintf(buf, 40, "%u", ntohs(tcp_hdr->source));	// grab TCP source port
				mapping_elems(buf, tcp_sportmap);
				memset(buf, 0x00, sizeof(buf));
				snprintf(buf, 40, "%u", ntohs(tcp_hdr->dest));	// grab TCP destination port similarly
				mapping_elems(buf, tcp_dportmap);

				//----------------- get TCP flags info ---------------------------------
				if (tcp_hdr->ack) {	// if the "ACK" flag is set
					if ( (itr = tcp_flagsmap.find("ACK")) != tcp_flagsmap.end() )
						itr->second++;
				} else if (tcp_hdr->fin) {	// if "FIN" flag is set
					if ( (itr = tcp_flagsmap.find("FIN")) != tcp_flagsmap.end() )
						itr->second++;
				} else if (tcp_hdr->psh) {	// if "PSH" flag is set
					if ( (itr = tcp_flagsmap.find("PSH")) != tcp_flagsmap.end() )
						itr->second++;
				} else if (tcp_hdr->rst) {	// if "RST" flag is set
					if ( (itr = tcp_flagsmap.find("RST")) != tcp_flagsmap.end() )
					itr->second++;
				} else if (tcp_hdr->syn) {	// if "SYN" flag is set
					if ( (itr = tcp_flagsmap.find("SYN")) != tcp_flagsmap.end() )
					itr->second++;
				} else if (tcp_hdr->urg) {	// if "URG" flag is set
					if ( (itr = tcp_flagsmap.find("URG")) != tcp_flagsmap.end() )
					itr->second++;
				} //----------------- end TCP flags info ---------------------------------
			break;
			
			case IPPROTO_UDP:	// UDP type
				memset(buf, 0x00, sizeof(buf));
				snprintf(buf, 40, "%hu", ntohs(udp_hdr->source));	// grab TCP source port
				mapping_elems(buf, udp_sportmap);	// insert into map
				memset(buf, 0x00, sizeof(buf));
				snprintf(buf, 40, "%hu", ntohs(udp_hdr->dest));	// grab TCP source port
				mapping_elems(buf, udp_dportmap);	// insert into map
				break;
			
			case IPPROTO_ICMP:	// ICMP type
				memset(buf, 0x00, sizeof(buf));
				snprintf(buf, 40, "%d", icmp_hdr->type);	// convert 8-bit unsigned int to 32-bit int
				mapping_elems(buf, icmp_typemap);	// insert into its respecive map
				memset(buf, 0x00, sizeof(buf));
				snprintf(buf, 40, "%d", icmp_hdr->code);	// convert 8-bit unsigned int to 32-bit int
				mapping_elems(buf, icmp_codemap);	// insert into its respecive map
				break;

			default:
				break;
		}

	} else if (ntohs(eth_hdr->h_proto) == ETH_P_ARP) { 	//----------------- ARP packet parsing -------------------------

		memset(buf, 0x00, sizeof(buf));	// flush-out buffer
		snprintf(buf, 40, "%02x:%02x:%02x:%02x:%02x:%02x", arp_hdr->__ar_sha[0], arp_hdr->__ar_sha[1], arp_hdr->__ar_sha[2], arp_hdr->__ar_sha[3], arp_hdr->__ar_sha[4], arp_hdr->__ar_sha[5]);	// each octet byte written in hex
		string sha(buf);	// char array to string

		memset(buf, 0x00, sizeof(buf));	// flush out buffer for reuse
		snprintf(buf, 40, "%d.%d.%d.%d", arp_hdr->__ar_sip[0], arp_hdr->__ar_sip[1], arp_hdr->__ar_sip[2], arp_hdr->__ar_sip[3]);	// grab sender IP address octets
		string arp_ip(buf);

		memset(buf, 0x00, sizeof(buf));
		snprintf( buf, 40, "%s / %s", sha.c_str(), arp_ip.c_str() );	// sender hardware address along with sender IP address
		string mac_ip(buf);
		mapping_elems(mac_ip, arp_map);	// insert into hash map
		//-------------------------------- end ARP parsing -------------------------------------------------------------

	} else {
		memset(buf, 0x00, sizeof(buf));	// flush-out buffer
		int dec_proto = ntohs(eth_hdr->h_proto);	// decimal form of some protocol found
		char hex_proto[10];	// to store hexadecimal form of a protocol found earlier
		snprintf(hex_proto, 10, "0x%x", dec_proto);
		snprintf(buf, 40, "%d (%s)", dec_proto, hex_proto);
		string proto_str(buf);	// convert to string
		mapping_elems(proto_str, mapofothers);
	}

}

/* 
 * mapping_ethaddr() -> void
 * 	inserts every source/destination ethernet addresses in a map
 */
void mapping_elems(string elem, map<string, int> &hmap) {
	if ( (itr = hmap.find(elem)) == hmap.end() )	// src eth addr is not already present in map
		hmap.insert( pair<string, int>(elem, 1) );	// insert new src eth addr & set its count to 1 initially
	else	// if src eth addr already present in map
		itr->second++;	// increase its count
}

/* set each TCP flag (ACK, FIN, etc.) to 0 initially */
void init_tcp_flagsmap(map<string, int> &hmap) {
	hmap["ACK"]	= 0;
	hmap["FIN"]	= 0;
	hmap["PSH"]	= 0;
	hmap["RST"]	= 0;
	hmap["SYN"]	= 0;
	hmap["URG"]	= 0;
}

/*
 * overloaded mapping elems function;
 * needed have this to avoid the "jump to case label crosses initilialization error"
 */
void mapping_elems(char * buffer, map<string, int> &anymap) {
	string str(buffer);	// convert to string
	mapping_elems(str, anymap);	// insert into map
}

/*
 * print_map() -> void
 * 	function prints contents of any map passed as argument
 */
 void print_map(map<string, int> &anymap) {
 	for ( itr = anymap.begin(); itr != anymap.end(); itr++)
 		cout << itr->first << "\t\t" << itr->second << endl;
 }

/*
 * this function counts the total number of unique fields stored as 'keys' in 
 * the map by adding each type's count and returning the final total count
 * count_unique() -> int
 */
 int count_unique(map<string, int> &anymap) {

 	int count = 0;
 	for (itr = anymap.begin(); itr != anymap.end(); itr++) {
 		count += itr->second;
 	}

 	return count;
 
 }