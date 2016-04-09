
/*
 * References:
 	* https://code.google.com/p/pcapsctpspliter/issues/detail?id=6
	* "Hacking: The Art of Exploitation, 2nd Edition" book
 */

// include declarations written in header corresponding to this file
#include "wt_lib.h"

// packet capture libraries
#include "/usr/include/netinet/ether.h"

// include standard libraries
#include <iostream>
#include <cstdlib>
#include <map>
#include <utility>

using namespace std;

// enter long options to be used at cli
static struct option long_options[] = {
	{"help",	no_argument,       0, 'h'},
	{"open",    required_argument, 0, 'o'},
	{0, 0, 0, 0}	// last element needs to be filled as all zeros
};

/* default constructor for class PacketParser */
PacketParser::PacketParser() {
	memset(this->filename, 0x00, sizeof(this->filename));	// initially zero-out contents of filename
}

/* parameterized constructor for class PacketParser 
 * sets filename 
 */
PacketParser::PacketParser(char *str) {
	memset(this->filename, 0x00, sizeof(this->filename));	// for case when default constructor is not called
	memcpy(this->filename, str, strlen(str));	// register filename provided at cli
}

/* instructions on using program command line options */
void usage(FILE *file) {
	if (file == NULL)
		file = stdout;	// set standard output by default

	fprintf(file, "wiretap [OPTIONS] example.pcap\n"
				"	-h or --help			Print this help screen\n"
                "        -o example.pcap         \n"
				"	 or --open example.pcap 	Open packet capture file 'example.pcap'\n");
}

char * PacketParser::get_filename() {
	return this->filename;
}

/*
 * parse_args() -> void
 * function that parses command line arguments to 'wiretap'
 */
void PacketParser::parse_args(int argc, char *argv[], PacketParser **wt_args) {	// pass PacketParser pointer-to-pointer to reach memory allocated in this function

    int g;	// grab return value of getopt_long()
    int option_index;	// array index that getopt_long() shall set
    while ( (g = getopt_long(argc, argv, "ho:", long_options, &option_index)) != -1) {
    	switch(g) {
    		case 'h':
    			usage(stdout);
                exit(1);
    			break;
     		case 'o':
    			*wt_args = new PacketParser(optarg);
    			break;
    		default:
 				usage(stdout);
    			exit(1);
                break;
    	}
    }

}