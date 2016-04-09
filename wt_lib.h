
/* 
 * references:
 	http://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
 */

#ifndef _WT_LIB_H_
#define _WT_LIB_H_

#include <cstdio>
#include <getopt.h>
#include <string>
#include <cstring>
#include <map>
#include "/usr/include/pcap/pcap.h"	// standard pcap library

/*
 * class to parse through all command line arguments and set up program 
 * initializer variables among other things.
 */
class PacketParser {
	private:
		char filename[100];
	public:
		PacketParser();	// default constructor
		PacketParser(char *);	// parameterized constructor
		void parse_args(int, char **, PacketParser **);	// scans through cli arguments
		char * get_filename();	// retrieve packet capture filename
};

/* instructions on using program command line options */
void usage(FILE *);

/* pcap_loop()'s callback routine */
void pcap_callback(u_char *, const struct pcap_pkthdr*, const u_char *);

/* parse_hdrs() parses different header-types in a packet */
void parse_hdrs(const u_char *);

/* mapping_ethaddr() inserts every source/destination ethernet addresses in a map */
void mapping_elems(std::string, std::map<std::string, int> &);

/* overloaded mapping elems function */
void mapping_elems(char *, std::map<std::string, int> &);

/* set each TCP flag (ACK, FIN, etc.) to 0 initially 
 * init_tcp_flagsmap() -> void
 */
void init_tcp_flagsmap(std::map<std::string, int> &);

/* print_map() prints contents of any map passed as argument */
void print_map(std::map<std::string, int> &);

/*
 * this function counts the total number of unique fields stored as 'keys' in 
 * the map by adding each type's count and returning the final total count
 * count_unique() -> int
 */
int count_unique(std::map<std::string, int> &);

#endif