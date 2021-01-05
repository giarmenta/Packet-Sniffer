/* Gerardo Armenta
*  10/31/2020
*  Packet sniffer program using pcap library. The sniffer code can
*  capture passwords from telnet. Source: http://www.tcpdump.org/pcap.htm
*/

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

// ethernet header is 14 bytes
#define SIZE_ETHERNET 14

/* IP header struct object */
struct sniff_ip {
        u_char  ip_vhl;                 
        u_char  ip_tos;                 
        u_short ip_len;                 
        u_short ip_id;                 
        u_short ip_off;                 
        #define IP_RF 0x8000            
        #define IP_DF 0x4000            
        #define IP_MF 0x2000            
        #define IP_OFFMASK 0x1fff       
        u_char  ip_ttl;                 
        u_char  ip_p;                   
        u_short ip_sum;                 
        struct  in_addr ip_src,ip_dst; 
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

	typedef u_int tcp_seq;
   /* TCP header struct object */
	struct sniff_tcp {
		u_short th_sport;	
		u_short th_dport;
		tcp_seq th_seq;	
		tcp_seq th_ack;	
		u_char th_offx2;
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		
		u_short th_sum;		
		u_short th_urp;	
};

/* This function prints payload found in packets */
void print_payload(char *payload, int len)
{
   char *pl = payload;
   int i;

   for(i = 0; i < len; i++)
   {
       if (isprint(*pl))
           printf("%c", *pl);       /* Prints data from packet */
       pl++;
   }
   printf("\n");
   return;
}

/* This function lets the user enter the port range */
char* get_range(char* keyword)
{
   char port_range[12];

   printf("Enter the port range:\n");
   printf("(EXAMPLE: 0-65535)\n");
   scanf("%s", port_range);            /* Gets user input */
   int len = strlen(port_range);
   port_range[len] = '\0';             /* Sets the end of user input, avoids segmentation faults */
   strcat(keyword, port_range);        /* Concatinates the keyword with the user's input */

   return keyword;
}

/* The packet is reviewed for its data payload which allows for sniffing passwords */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
   printf("\nGot a packet\n");

	const struct sniff_ip *ip; 
	const struct sniff_tcp *tcp; 
	const char *payload; 

   int size_ip;
	int size_tcp;
   int size_payload;

   /* Defines the header for the payload */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
   tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* Prints the source and destination. Converts internet num to ASCII */
	printf("Source: %s\n", inet_ntoa(ip->ip_src));
	printf("Destination: %s\n", inet_ntoa(ip->ip_dst));
	
	/* checks what protocol the packet transfer is using and provides such information */	
	switch(ip->ip_p) 
   {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			break;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			return;
	}

   /* set up the payload data and prints with print_payload() */
   payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
   size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
   print_payload(payload, size_payload);
}

int main(int argc, char *argv[])
{
   pcap_t *handle;                                           // This is the session
   char errbuf[PCAP_ERRBUF_SIZE];                            // Device target and Error string
   struct bpf_program fp;                                    // Compiled filter expression
   char filter_exp[] = "tcp and "; //"tcp and port 23";    // "tcp and ";    // "icmp and host 000.000.0.000 and dst 000.000.0.000";
   bpf_u_int32 net;                                          // IP of sniffing device 
   // Step 1: Open live pcap session on NIC with name ethx
   // you need to change "eth3" to the name
   // found on their own machines (using ifconfig).

   /* Gets user input for the port range */
   char keyword[] = "portrange ";
   char *range = get_range(keyword);
   strcat(filter_exp, range);

   /* Checks for device name and for errors */
   if (pcap_lookupdev(*errbuf) == NULL) 
   {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return(2);
   }

   /* Checks for error when opening device to sniff on */
   handle = pcap_open_live(pcap_lookupdev(*errbuf), BUFSIZ, 1, 1000, errbuf);  // pcap_lookupdev(*errbuf) can be used instead of "eth0" 
   if (handle == NULL)
   {
      fprintf(stderr, "Can't open device %s: %s\n", pcap_lookupdev(*errbuf), errbuf);
      return(2);
   }

   // Step 2: Compile filter_exp into BPF psuedo-code
   /* filter compile check */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
   {
      fprintf(stderr, "Can't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return(2);
   }
   /* filter set is revised */
   if (pcap_setfilter(handle, &fp) == -1)
   {
      fprintf(stderr, "Can't initiate filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return(2);
   }
   // Step 3: Capture packets
   pcap_loop(handle, -1, got_packet, NULL);
   pcap_close(handle); // Closes the device handle
   return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap