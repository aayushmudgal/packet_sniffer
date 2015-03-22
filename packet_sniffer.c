/*
Group 16 - Packet Sniffer
Computer Networks, CS425 (2014-15 Sem 1)

Sidharth Guta		11714
Chetan Dalal		11218
Ayush Mudgal		12008
Dheeraj Agarwal		10

Command line instructions:
$gcc packet_sniffer.c -lpcap
$sudo ./a.out

Press Ctrl+C to exit
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#define ETHERNET_HEADER_SIZE 14

//structure of ethernet header
struct	ethernet_header {
	u_char	ethernet_dhost[ETHER_ADDR_LEN];		//destination host address
	u_char	ethernet_shost[ETHER_ADDR_LEN];		//source host address
	u_short	ethernet_type;						//type of packet
};

//structure of ip header 
struct ip_header {
	u_char version;				//version<<4 | header length >> 2
	u_char TOS;					//type of service
	u_char headerLen;				//header length
	u_char ID;					//identification
	u_char fragOffset;					//fragment offset
	#define IP_RF 0x8000			//reserved fraagment
	#define IP_DF 0x4000			//don't fragment
	#define IP_MF 0x2000			//more fragments
	#define IP_OFFMASK 0x1fff		//mask for fragmenting bits
	u_char TTL;					//time to live
	u_char protocol;					//protocol
	u_char checksum;				//checksum
	struct in_addr source, destination;	//source and destination addresses
};

//tcp-header structure
struct tcp_header {
	u_short sourcePort;			//Source Port
	u_short dstPort;			//Destination Port
	u_int seqNo;				//Sequence Number
	u_int ackNo;				//Acknowledgement number
	u_char offset;					//data offset, reserved bits
	u_char tcpFlags;				//tcp control bits and ecn options
	#define TCP_FIN  0x01
    #define TCP_SYN  0x02
    #define TCP_RST  0x04
    #define TCP_PUSH 0x08
    #define TCP_ACK  0x10
    #define TCP_URG  0x20
    #define TCP_ECE  0x40
    #define TCP_CWR  0x80
    #define TCP_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)	
	u_short recvWin;				//window size
	u_short checksum;				//checksum
	u_short urgent;				//urgent pointer
};

//icmp-header structure
struct icmp_header {
	u_char type;				//icmp type
	u_char code;				//icmp code 
	u_short checksum;				//icmp checksum
	u_int data;				//other data
};

//udp-header structure
struct udp_header {
	u_short sourcePort;			//source port
	u_short dstPort;			//destination port
	u_short headerLen;				//header length
	u_short checksum;				//check sum
};

//filter for packets
struct filter {
	char *ip;
	int protocol;
};

struct filter filter_exp;

struct iptoip
{
	char *ip1;
	char *ip2;
	long long int size;
};

struct iptoip *iparray;
long long int totalCount=0,udpCount=0,tcpCount=0,icmpCount=0;

void packet_receive(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_ethernet_header(FILE *fp, const u_char *packet);
int print_ip_header(FILE *fp, const u_char *packet, u_char *protocol, int size);
int print_tcp_header(FILE *fp, const u_char *packet, int ip_hdr_size);
int print_icmp_header(FILE *fp, const u_char *packet, int ip_hdr_size);
int print_udp_header(FILE *fp, const u_char *packet, int ip_hdr_size);
void print_data(const u_char *data, int size);

//Pointer to file in which output is written
FILE *logfile;
struct timeval tp_start, tp_end;
clock_t begin, end;
double time_spent;
char **ipname;
char *device = NULL;
int n;
char devices_array[100][100];
int ipcount=0;
int ip4=0, ip6=0;
long long int totalSize=0;
char filename[256];
int iptoipcount=0;
typedef int (*compfn)(const void*, const void*);


void cleanup_and_exit (int signo)
{

	gettimeofday(&tp_end, NULL);

	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

	if(totalCount)
	{
	printf("\n-------------------------Packet Sniffing Statistics------------------------------\n");
	printf("\n\t Complete log is stored in file: %s\n",filename);
	printf("\n\t Device Monitored: %s",devices_array[n]);
	printf("\n\t\t Total time the packets were sniffed: %lf seconds\n",time_spent);
	printf("\t\t Total Number of Packets Sniffed: %lld\n",totalCount);
	printf("\t\t Total Number of IPv4 packets: %d\n",ip4);
	printf("\t\t Total Number of IPv6 packets: %d\n",ip6);
	printf("\t\t Total Number of IP's monitored: %d\n",ipcount);
	printf("\t\t Total amount of data flowing across is %lld bytes\n",totalSize/8);
	printf("\t\t TCP header count: %lld\n", tcpCount);
	printf("\t\t UDP header count: %lld\n", udpCount);
	printf("\t\t ICMP header count: %lld\n", icmpCount);

	printf("\n-------------------------IP to IP data-flow--------------------------------------\n");
	int k=0;
                 // Pointer to compare function

	for(k=0;k<iptoipcount;k++)
	{
		printf("\t\t IP Address %s and IP Address %s : Total Data Flow: %lld bytes\n",iparray[k].ip1,iparray[k].ip2, iparray[k].size);
	}



	printf("\n-------------------------Total IP's Monitored------------------------------------\n");
	
	
	for(k=0;k<ipcount;k++)
	{
		printf("\t\tIP Address: %s\n",ipname[k]);
	}
	}

	printf("\n---------------------------------------------------------------------------------\n");	

	exit(0);
}


int main()
{
	ipname=(char **)calloc(99999,sizeof(char *));
	iparray = (struct iptoip *)calloc(10000,sizeof(struct iptoip ));
	
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct in_addr address;
	pcap_if_t *all_devices, *device_t;
	int count = 1;
	int i=1;
	for (i=1; i<=19; i++) {
        	signal(i, cleanup_and_exit);					// Storing information on closing the packet sniffer
	}
	//find all available devices
	printf("Welcome to GROUP-16 PACKET SNIFFER\n");
    if( pcap_findalldevs( &all_devices , error_buffer) )
    {
        printf("ERROR: Devices not found : %s" , error_buffer);
        exit(1);
    }
    printf("Please mention the name where you wish the log to be saved\n");
   
    scanf("%s",filename);
     
   //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device_t = all_devices ; device_t != NULL ; device_t = device_t->next)
    {
        printf("%d. %s - %s\n" , count , device_t->name , device_t->description);
        if(device_t->name != NULL)
        {
            strcpy(devices_array[count] , device_t->name);
        }
        count++;
    }
     
    //Ask user which device to sniff
    printf("Enter the number of the device to monitor: \n");
    scanf("%d" , &n);
	if (n >= count)
	{
		printf("ERROR: Invalid option entered by user");
		return 0;
	}
	device = devices_array[n];

	//network number
	bpf_u_int32 net_num;
	//subnet mask number
	bpf_u_int32 subnet_mask;

	//looks up the device for network number and subnet mask
	if (pcap_lookupnet(device, &net_num, &subnet_mask, error_buffer))
	{
		printf("ERROR: Could not determine IP address and subnet mask of selected device");
		return 0;
	}
	address.s_addr = net_num;
	printf("Network Number: %s\n", inet_ntoa(address));
	address.s_addr = subnet_mask;
	printf("Subnet mask: %s\n", inet_ntoa(address));

	//creates a pcap_t handle descriptor
	pcap_t *descriptor;

	//open a live device and binds it to the handle descriptor
	descriptor = pcap_open_live(device,BUFSIZ, 1, 0, error_buffer);
	if(descriptor==NULL)
	{
		printf("ERROR: Could not open device %s\n", device);
		return 0;
	}

	//open a file to store the sniffing result
	logfile = fopen(filename, "w");

	char ip[13];
	struct bpf_program fp;
	char ch;
	i=0;
	
	ch=getchar();
	int p;
	printf("Enter IP addr of node to monitor in terminal. Press enter if this is not desired\n");
	while((ch=getchar())!='\n')
	{
		ip[i]=ch;
		i++;
	}
	ip[i]='\0';
	filter_exp.ip = ip;

	printf("Enter the protocol of packets to monitor in terminal:\n0:ignore\n1:TCP \n2:UDP \n3:ICMP \n");
	scanf("%d", &p);

	printf("For all packets header data and payload see the file %s\n",filename);

	if(p == 1) 
		filter_exp.protocol = IPPROTO_TCP;
	else if(p == 2) 
		filter_exp.protocol = IPPROTO_UDP;
	else if(p == 3) 
		filter_exp.protocol = IPPROTO_ICMP;
	printf("%d",filter_exp.protocol);
	
	 gettimeofday(&tp_start, NULL);
	 
	long long int no=-1;
	printf("Enter the number of packets to be sniffed before stopping\n");
	printf("\t Print any negative integer to loop infinately. Press Ctrl+C to stop the packet sniffer\n");
	scanf("%lld",&no);
	if(no<0)
	{
		no=-1;
	 
	}
	begin = clock();

	//go in an infinte loop and execute packet_receive function for sniffing
	pcap_loop(descriptor, no, packet_receive, NULL);
	kill(getpid(), 2); 
}

/*--------------------------------------------------------------------------------------------------------------------------------*/

void packet_receive(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	struct in_addr source, destination;
	u_char protocol;
	int proto_hdr_size;
	totalCount++;
	fprintf(logfile,"\nPACKET LENGTH: %d\n", header->len);

	//print the ethernet header
	print_ethernet_header(logfile,packet);

	//return the ip header size and pass the protocol in the argument, printing ip header
	int ip_hdr_size = print_ip_header(logfile,packet,&protocol,header->len-(ETHERNET_HEADER_SIZE+ip_hdr_size));
	
	//print the appropriate protocol header  and return the header size
	if(protocol == IPPROTO_TCP){
	proto_hdr_size = print_tcp_header(logfile,packet,ip_hdr_size);}

	if (protocol == IPPROTO_ICMP){
	proto_hdr_size = print_icmp_header(logfile,packet,ip_hdr_size);}

	if (protocol == IPPROTO_UDP) {
	proto_hdr_size = print_udp_header(logfile,packet, ip_hdr_size);}

	//print the data payload removing the ethernet and ip header
	print_data(packet+ETHERNET_HEADER_SIZE+ip_hdr_size, header->len-(ETHERNET_HEADER_SIZE+ip_hdr_size));

	fprintf(logfile, "\n\n-----------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
}

/*--------------------------------------------------------------------------------------------------------------------------------*/

void print_ethernet_header(FILE *fp, const u_char *packet)
{
	struct ethernet_header *etherhdr; 
	//extracts the ethernet header from the packet
	etherhdr = (struct ethernet_header *) packet;

	fprintf(fp,"\n		ETHERNET HEADER		\n");

	//prints the ethernet type
    if (ntohs (etherhdr->ethernet_type) == ETHERTYPE_IP)
    {
        fprintf(fp, "\t|-Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(etherhdr->ethernet_type),
                ntohs(etherhdr->ethernet_type));
    }else  if (ntohs (etherhdr->ethernet_type) == ETHERTYPE_ARP)
    {
        fprintf(fp,"\t|-Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(etherhdr->ethernet_type),
                ntohs(etherhdr->ethernet_type));
    }else {
        fprintf(fp,"\t|-Ethernet type %x not IP\n", ntohs(etherhdr->ethernet_type));
    }
	
	int i;
	u_char *ptr;

	//extracting destinantion host address and printing
    ptr = etherhdr->ethernet_dhost;
    i = ETHER_ADDR_LEN;
    fprintf(fp,"\t|-Destination Ethernet Address:  ");
    do{
        fprintf(fp, "%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    fprintf(fp,"\n");

	//extracting source host address and printing
    ptr = etherhdr->ethernet_shost;
    i = ETHER_ADDR_LEN;
    fprintf(fp,"\t|-Source Ethernet Address:  ");
    do{
        fprintf(fp,"%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    fprintf(fp,"\n");
	//printing the protocol field of ethernet
	fprintf(fp,"\t|-Protocol : %x\n", ntohs(etherhdr->ethernet_type));	
}

/*--------------------------------------------------------------------------------------------------------------------------------*/

int print_ip_header(FILE *fp, const u_char *packet, u_char *protocol,int size)
{
	fprintf(fp,"\n			IP HEADER			\n");

	struct ip_header *iphdr;
	int ip_hdr_size;

	//extracts the ip heaeder from the packet
	iphdr=(struct ip_header *)(packet+ETHERNET_HEADER_SIZE);
	
	//printing the ip header fields
	fprintf(fp,"\t|-Version : %d\n", iphdr->version>>4);
	if(iphdr->version>>4==4)
	{
		ip4++;
	}
	else
	{
		ip6++;
	}
	fprintf(fp,"\t|-Header length : %d\n", (iphdr->version & 0x0f)*4);
	fprintf(fp,"\t|-Source ip: %s\n", inet_ntoa(iphdr->source));
	int k=0, flag=0,curr=0,curr1=1;
	int flag1=0;
	for(k=0;k<ipcount;k++)
	{
		
		if(strcmp(ipname[k],inet_ntoa(iphdr->source))==0)
										//ipname stored
			{														//curr is the name of current ip
				flag=1;
				curr=k;
				break;
			}

	}
	if(!flag)
	{
		ipname[ipcount]=(char *)calloc(1,sizeof(inet_ntoa(iphdr->source)));
		strcpy(ipname[ipcount],inet_ntoa(iphdr->source));
		curr=ipcount;
	
		ipcount++;
		
	}


	flag=0;

	fprintf(fp,"\t|-Destination ip: %s\n", inet_ntoa(iphdr->destination));
	
	for(k=0;k<ipcount;k++)
	{
		if(strcmp(ipname[k],inet_ntoa(iphdr->destination))==0)				//ipname stored
			{														//curr1 is the name of current ip
				flag=1;
				curr1=k;
				break;
			}
	}
	if(!flag)
	{	
		ipname[ipcount]=(char *)calloc(1,sizeof(inet_ntoa(iphdr->destination)));
		strcpy(ipname[ipcount],inet_ntoa(iphdr->destination));
		curr1=ipcount;
		
		ipcount++;
	}

	int t=0; 
	flag=0;
	for(t=0;t<iptoipcount;t++)
	{
		if(strcmp(iparray[t].ip1,inet_ntoa(iphdr->source))==0&& (strcmp(iparray[t].ip2,inet_ntoa(iphdr->destination))==0))
		{
			flag=1;
			iparray[t].size+=size/8;
			
			break;
		}
		if(strcmp(iparray[t].ip2,inet_ntoa(iphdr->source))==0&& (strcmp(iparray[t].ip1,inet_ntoa(iphdr->destination))==0))
		{
			flag=1;
			iparray[t].size+=size/8;
			//printf("HEre 2\n");
			break;
		}
		
	}
	if(!flag)
	{
		iparray[iptoipcount].ip1= (char *)calloc(1,sizeof(inet_ntoa(iphdr->source)));
		iparray[iptoipcount].ip2= (char *)calloc(1,sizeof(inet_ntoa(iphdr->destination)));
		strcpy(iparray[iptoipcount].ip1,inet_ntoa(iphdr->source));
		strcpy(iparray[iptoipcount].ip2,inet_ntoa(iphdr->destination));
		iparray[iptoipcount].size=size/8;
		iptoipcount++;
	//	printf("IPtoip count %d\n",iptoipcount);
	}





	fprintf(fp,"\t|-Type of service: %u\n", iphdr->TOS);
	fprintf(fp,"\t|-Time to live: %d\n",iphdr->TTL);
	fprintf(fp,"\t|-Ip protocol: %u\n", iphdr->protocol);
	fprintf(fp,"\t|-Checksum : %d\n", iphdr->checksum);	
	*protocol=iphdr->protocol;

	ip_hdr_size = (iphdr->version & 0x0f)*4;
	
	if(filter_exp.protocol==0 && filter_exp.ip[0]==0)
		return ip_hdr_size;

	//printing the filtered header
	if((*protocol==filter_exp.protocol || filter_exp.protocol==0) && (!strcmp(inet_ntoa(iphdr->destination),filter_exp.ip) || !strcmp(inet_ntoa(iphdr->source),filter_exp.ip) || filter_exp.ip[0]==0))
	{
		printf("\n		IP HEADER		\n");
		printf("\t|-Version : %d\n", iphdr->version>>4);
		printf("\t|-Header length : %d\n", (iphdr->version & 0x0f)*4);
		printf("\t|-Source ip: %s\n", inet_ntoa(iphdr->source));
		printf("\t|-Destination ip: %s\n", inet_ntoa(iphdr->destination));
		printf("\t|-Type of service: %u\n", iphdr->TOS);
		printf("\t|-Time to live: %d\n",iphdr->TTL);
		printf("\t|-Ip protocol: %u\n", iphdr->protocol);
		printf("\t|-Checksum : %d\n", iphdr->checksum);

		//printing tcp header according to filter
		if(*protocol==IPPROTO_TCP)
		{
			print_tcp_header(stdout,packet,ip_hdr_size);
		}
		
		//printing udp header according to filter
		else if(*protocol==IPPROTO_UDP)
		{
			print_udp_header(stdout,packet, ip_hdr_size);
		}

		//printing icmp header according to filter
		else if(*protocol==IPPROTO_ICMP)
		{
			print_icmp_header(stdout,packet,ip_hdr_size);
		}
	}

	done:
	return ip_hdr_size;
}

/*--------------------------------------------------------------------------------------------------------------------------------*/

int print_tcp_header(FILE *fp, const u_char *packet, int ip_hdr_size)
{
	fprintf(fp,"\n			TCP HEADER			\n");

	struct tcp_header *tcphdr;
	int tcp_hdr_size;

	//extracts tcp header 
	tcphdr=(struct tcp_header *)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);

	//printing the tcp header fields
	fprintf(fp,"\t|-Source Port: %u\n", ntohs(tcphdr->sourcePort));
	fprintf(fp,"\t|-Destination Port: %u\n", ntohs(tcphdr->dstPort));
	fprintf(fp,"\t|-Sequence Number: %u\n", ntohl(tcphdr->seqNo));
	fprintf(fp,"\t|-Acknowledgement: %u\n", ntohl(tcphdr->ackNo));
	fprintf(fp,"\t|-Header length: %d\n", (tcphdr->offset & 0xf0)*4);
	fprintf(fp,"\t|-Flags: %u\n", tcphdr->tcpFlags);
	fprintf(fp,"\t|-Window: %d\n", ntohs(tcphdr->recvWin));
	fprintf(fp,"\t|-Checksum %d\n", ntohs(tcphdr->checksum));
	fprintf(fp,"\t|-Urgent pointer: %d\n", ntohs(tcphdr->urgent));
	tcp_hdr_size=(tcphdr->offset & 0xf0)*4;
	tcpCount++;
	return tcp_hdr_size;
}

/*--------------------------------------------------------------------------------------------------------------------------------*/

int print_icmp_header(FILE *fp, const u_char *packet, int ip_hdr_size)
{
	struct icmp_header *icmphdr;
	int icmp_hdr_size=8;

	//extracts icmp header
	icmphdr=(struct icmp_header*)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);

	//printing the icmp header fields
	fprintf(fp,"\n			ICMP HEADER			\n");
	fprintf(fp,"\t|-ICMP Type: %u\n", icmphdr->type);
	fprintf(fp,"\t|-ICMP Code: %u\n", icmphdr->code);
	fprintf(fp,"\t|-ICMP CheckSum: %d\n", ntohs(icmphdr->checksum));
	fprintf(fp,"\t|-ICMP Data: %d\n", icmphdr->data);
	icmpCount++;
	return icmp_hdr_size;		
}

/*--------------------------------------------------------------------------------------------------------------------------------*/

int print_udp_header(FILE *fp, const u_char *packet, int ip_hdr_size)
{
	struct udp_header *udphdr;
	int udp_hdr_size=8;

	//extracts udp header
	udphdr=(struct udp_header*)(packet+ETHERNET_HEADER_SIZE+ip_hdr_size);

	//printing the udp header fields
	fprintf(fp,"\n			UDP HEADER			\n");
	fprintf(fp,"\t|-UDP Source Port: %d\n", ntohs(udphdr->sourcePort));
	fprintf(fp,"\t|-UDP Destination Port: %d\n", ntohs(udphdr->dstPort));
	fprintf(fp,"\t|-UDP Length: %d\n",ntohs(udphdr->headerLen));
	fprintf(fp,"\t|-UDP CheckSum: %d\n", ntohs(udphdr->checksum));
	udpCount++;
	return udp_hdr_size;		

}

/*--------------------------------------------------------------------------------------------------------------------------------*/

//printing data in row of 32 bytes 	<hex>	<ascii>
void print_data(const u_char *data, int size)
{
	int i,j;
	totalSize=totalSize+size;
	fprintf(logfile,"\n\tPAYLOAD\n");
	for(i=0;i<size;i++)
	{
		fprintf(logfile,"%02X  ", (u_int)data[i]);
		if(i%32==0)
		{
			fprintf(logfile,"		");
			if(i!=0)
			{
				for(j=i-32;j<i;j++)
				{
					if(data[j]>=32 && data[j]<=126)
						fprintf(logfile,"%c",(u_char)data[j]);
					else
						fprintf(logfile,".");
				}
			}
			fprintf(logfile,"\n");
		}
	}
}
