/* Packet sniffer using libpcap library */
// Group : ArchNET
// File : pcaptestWThdr+Chksum.c
// Lab06 : IP Routing

#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>     //Thread creation & management
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <pcap.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <net/ethernet.h>
#include <arpa/inet.h> // for inet_ntoa()
#include "lpm.h"
#include "iprt.h"

/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
typedef struct arphdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
}arphdr_t;

#define MAXBYTES2CAPTURE 2048

#define LAN_IP "10.99.0.3"
#define LINK_IP "10.10.0.2"
#define IFACE_LAN   "eth4"
#define IFACE_NODE0 "eth2"

struct thread_data{
    u_char *buffer;
    int size;
};

//Function Declaration
void process_packet(u_char *, const struct pcap_pkthdr *, u_char *);
void process_packet_lan(u_char *, const struct pcap_pkthdr *, u_char *);

struct iphdr *print_ip_header(u_char * , int);
void *print_tcp_packet(void *threadarg);
//void *print_udp_packet(void *threadarg);
void print_udp_packet(u_char * , int);
//void *print_icmp_packet(void *threadarg);
void print_icmp_packet(u_char * , int );
//void *print_arp_packet(void *threadarg);
void print_arp_packet(u_char *, int);
void print_ethr_header(u_char * );
void PrintData (const u_char * , int);
unsigned short cksum(uint16_t *, int );
int getMACnIface(char [], u_char [], char []);
void send_ether(u_char * ,u_char* ,u_char* , int );
int print_ip_header1(u_char ** Buffer, int *Size);
int print_icmp_echoreply(u_char ** BufferRef, int *Size); 

//Global Declaration
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,arp=0,total=0,i,j;
struct ipTableEntry ipte[2];
u_char srcAddr[6];
struct lpm_tree* tree = NULL;

int id=0;

pcap_t *handle = NULL; //Handle of the device that shall be sniffed
pcap_t *handle_lan = NULL;

int main()
{
	//Set MAC Addr of interface to send out packets
    //00:18:8b:41:60:15
    srcAddr[0]=0x00;
    srcAddr[1]=0x11;
    srcAddr[2]=0x43;
    srcAddr[3]=0xd3;
    srcAddr[4]=0x8e;
    srcAddr[5]=0x2d;
    
    char errbuf[100] , devname[20], devname2[20];
        	
    //initialize tree
    tree = lpm_init();
    
    //declare table
    u_char mac[6];
    char interface[10];
	
    //insert router table
    char ip_string[40];
    int mask;
    
    // Create Structure to store and search IP+Mask
    // Network through Router 1
    sscanf("10.1.0.0 24", "%39s %d%*[^\n]", ip_string, &mask);
    lpm_insert(tree, ip_string, mask);
    // Network through Router 2
    sscanf("10.1.0.0 16", "%39s %d%*[^\n]", ip_string, &mask);
    lpm_insert(tree, ip_string, mask);
    
    //Get MAC address
    getMACnIface("10.99.0.1", mac, interface);
    //Insert in Table
    insertTable(&ipte[0], "10.1.0.0", 24, "10.99.0.1", mac, interface);
    
    //Get MAC address 2
    getMACnIface("10.99.0.2", mac, interface);
    //Insert in Table
    insertTable(&ipte[1], "10.1.0.0", 16, "10.99.0.2", mac, interface);
    
    //Print Table
    printTable(ipte, 2);
    
    //Open the device for sniffing
    strcpy(devname, IFACE_NODE0);
    printf("Interface to sniff : %s \n" , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 1000 , errbuf);
    
    if (handle == NULL) {
      fprintf(stderr, "ERROR: Unable to open device %s : %s\n" , devname , errbuf);
      exit(1);
    }
    
    strcpy(devname2, IFACE_LAN);
    printf("Interface to sniff : %s \n" , devname2);
    handle_lan = pcap_open_live(devname2 , 65536 , 1 , 1000 , errbuf);
    
    if (handle_lan == NULL) {
      fprintf(stderr, "ERROR: Unable to open device %s : %s\n" , devname2 , errbuf);
      exit(1);
    }
    
    
    printf("\nSUCCESS: Opened device to sniff\n");
    
    //Set Direction of sniffing
    if(pcap_setdirection(handle, PCAP_D_IN)) {
      printf("set direction error\n");
    } else {
        printf("set direction success\n");
    }
    
    if(pcap_setdirection(handle_lan, PCAP_D_IN)) {
      printf("set direction error\n");
    } else {
        printf("set direction success\n");
    }
    
    // get file descriptor for two interfaces
    int handle_fd = pcap_get_selectable_fd(handle);
    int handle_lan_fd = pcap_get_selectable_fd(handle_lan);
    
    printf("%d\n", handle_fd);
    printf("%d\n", handle_lan_fd);
    
    
    
    fd_set sniff_fds;
    //memset(&sniff_fds, 0, sizeof(fd_set));
    FD_ZERO(&sniff_fds);
    FD_SET(handle_fd, &sniff_fds);
    FD_SET(handle_lan_fd, &sniff_fds);
    
    int higher_fd = (handle_fd > handle_lan_fd)?handle_fd:handle_lan_fd;
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1000;
    
    
    //u_char *pBuffer = NULL;
    //struct pcap_pkthdr *header = NULL;
    
    while(1) {
      
      FD_ZERO(&sniff_fds);
      FD_SET(handle_fd, &sniff_fds);
      FD_SET(handle_lan_fd, &sniff_fds);
	  
      int retval = select(higher_fd+1, &sniff_fds, NULL, NULL, &timeout);
      
      if(retval == 0) {
	continue;
      }
      
      if(FD_ISSET(handle_fd, &sniff_fds)) {
	
	pcap_loop(handle , 1 ,(pcap_handler) process_packet , NULL);
	
      } else if(FD_ISSET(handle_lan_fd, &sniff_fds)) {
	pcap_loop(handle_lan , 1 ,(pcap_handler) process_packet_lan , NULL);;
      }
      //Put the device in sniff loop
	  
      
    }
    
    return 0;
}

int getMACnIface(char ip[], u_char mac[], char iface[]) {
    
	FILE *arp = fopen("/proc/net/arp", "rb");
	if(arp == NULL) {

	  return 0;

	} else {
	  
	  char buffer[150];
	  char ipBuf[20];
	  char macBuf[30];
	  char ifaceBuf[10];
	  
	  fgets(buffer, 150, arp);
	  
	  while(1) {
	    
	    if(fscanf(arp, "%s %*s %*s %s %*s %s \n", ipBuf, macBuf, ifaceBuf) != EOF){
	      
	      if(!strcmp(ip, ipBuf)) {
		
		printf("Found %s : %s %s\n", ip, macBuf, ifaceBuf);
                
		strcpy(iface, ifaceBuf);
                
		char *macPtr = macBuf;
		char *pch = NULL;
		uint32_t tmp;
                
		pch = strchr(macPtr, ':');
		*pch++ = '\0';
		sscanf(macPtr, "%02X", &tmp);
		mac[0] = tmp;
		
		macPtr = pch;
		pch = strchr(pch, ':');
		*pch++ = '\0';
		sscanf(macPtr, "%02X", &tmp);
		mac[1] = tmp;
                
		macPtr = pch;
		pch = strchr(pch, ':');
		*pch++ = '\0';
		sscanf(macPtr, "%02X", &tmp);
		mac[2] = tmp;
                
		macPtr = pch;
		pch = strchr(pch, ':');
		*pch++ = '\0';
		sscanf(macPtr, "%02X", &tmp);
		mac[3] = tmp;
                
		macPtr = pch;
		pch = strchr(pch, ':');
		*pch++ = '\0';
		sscanf(macPtr, "%02X", &tmp);
		mac[4] = tmp;
		
		macPtr = pch;
		pch = strchr(pch, '\0');
		sscanf(macPtr, "%02X", &tmp);
		mac[5] = tmp;
                
		fclose(arp);
		return 1;
                
	      }
	    } else {
	      
	      printf("Target IP cannot be found\n");
	      fclose(arp);
	      return 0;
	    }
	  }
	}
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, u_char *buffer)
{
    int size = header->len;
        
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    
    ++total;
	
    //Check the Protocol and act accordingly
    switch (iph->protocol) {
        case 1:  //ICMP Protocol
            ++icmp;
            
            print_icmp_packet(buffer, size);
            
            break;
            
        case 2:  //IGMP Protocol
            ++igmp;
            break;
            
        case 6:  //TCP Protocol
            
            ++tcp;
            
            break;
            
        case 17: //UDP Protocol
            
            ++udp;
            
	    print_udp_packet(buffer, size);
	    break;
            
            
    default: //Some Other Protocol like ARP etc.
            if(iph->protocol == 4) {

                if(buffer[12] == 0x08 && buffer[13] == 0x06) {
                  
		  print_arp_packet(buffer, size);
		  
		  arp++;
                } else {
                    ++others;
                }

            } else {
	      ++others;
            }
            break;
    }
}

void process_packet_lan(u_char *args, const struct pcap_pkthdr *header, u_char *buffer)
{
    
    int size = header->len;
    
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    
    struct sockaddr_in tmp_src;
    tmp_src.sin_addr.s_addr = iph->saddr;

    if(strcmp(inet_ntoa(tmp_src.sin_addr), LAN_IP)) {

      ++total;
	
      //Check the Protocol and act accordingly
      switch (iph->protocol) {
      case 1:  //ICMP Protocol
	++icmp;
        
	print_icmp_packet(buffer, size);
	break;
        
      case 2:  //IGMP Protocol
	++igmp;
	break;
        
      case 6:  //TCP Protocol
	
	++tcp;
	
	break;
        
      case 17: //UDP Protocol
	
	++udp;
	
	print_udp_packet(buffer, size);
	break;
        
        
      default: //Some Other Protocol like ARP etc.
	/*
	  if(iph->protocol == 4) {
	  if(buffer[12] == 0x08 && buffer[13] == 0x06) {
	  //rc = pthread_create(&thread, NULL, print_arp_packet, (void *)&td);
	  print_arp_packet(buffer, size);
	  //if (rc){
	  //				printf("\nERROR: pthread_create() %d\n", rc);
	  //				exit(-1);
	  //			}
	  arp++;
	  } else {
	  ++others;
	  }
	  } else {
	  ++others;
	  }
	*/
	++others;
	break;
      }
    }
}

//Print Ethernet Header
void print_ethr_header(u_char * Buffer) {
    
    int i=0;
    printf("\nEthernet Header Contents\n");
	
    printf("\nDestination MAC addr: ");
    for(i=0; i<6; i++) {
        printf("%02X:", Buffer[i]);
    }
    
    printf("\nSource MAC addr: ");
    for(; i<12; i++) {
        printf("%02X:", Buffer[i]);
    }
    
    printf("\nEtherType: ");
    for(; i<sizeof(struct ethhdr); i++) {
        printf("%02X", Buffer[i]);
    }
    printf("\n");
}

//For ICMP Packet
void print_icmp_packet(u_char * Buffer , int Size) {
    
    u_char* macAddr;
    char dest_ip[40];
    int mask = 0;
    char output[100];
	
    print_ethr_header(Buffer);
    
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    
    fprintf(stdout , "\nICMP Packet Contents\n");
    
    fprintf(stdout , "\n");
    
    fprintf(stdout , "ICMP Header\n");
    fprintf(stdout , "Type : %d",(unsigned int)(icmph->type));
    
    if((unsigned int)(icmph->type) == 11) {
      fprintf(stdout , "  (TTL Expired)\n");
    } else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
      fprintf(stdout , "  (ICMP Echo Reply)\n");
    }
    fprintf(stdout , "Code : %d\n",(unsigned int)(icmph->code));
    fprintf(stdout , "Checksum : %d\n",ntohs(icmph->checksum));
    fprintf(stdout , "ID       : %d\n",ntohs(icmph->un.echo.id));
    fprintf(stdout , "Sequence : %d\n",ntohs(icmph->un.echo.sequence));
    fprintf(stdout , "\n");
    
    if(!(strcmp(inet_ntoa(dest.sin_addr),"10.10.0.1")) || 
       !(strcmp(inet_ntoa(dest.sin_addr),"10.99.0.1")) ||
       !(strcmp(inet_ntoa(dest.sin_addr),"10.99.0.2"))) {

      fprintf(stdout , "\nDo Nothing For Packets sent to Node0 and over LAN\n\n");

    } else if((strcmp(inet_ntoa(dest.sin_addr),"10.10.0.2")==0  || 
	       strcmp(inet_ntoa(dest.sin_addr),"10.99.0.3")==0) && 
	      (unsigned int)icmph->type==8) {

      fprintf(stdout , "\nSending ECHO Reply from usRTR\n");
      if(print_icmp_echoreply(&Buffer,&Size)) {
	
	u_char ourMAC[6] = {};
	u_char rplyMAC[6] = {};
	memcpy(rplyMAC, Buffer+6, 6);
	memcpy(ourMAC, Buffer, 6);
	  
	send_ether(Buffer, rplyMAC, ourMAC, Size);
	printf("**********************sent time exceeded msg************************\n");
	
        
      }

    } else {
        
      //Update IP Header
      iph = print_ip_header(Buffer,Size);
      printf("Update Of IP Done\n");
      //Look up IP for network
      lookupIP(inet_ntoa(dest.sin_addr), tree, output);
      
      printf("Look up IP Done\n");
      printf("%s\n",output);
      
      if(strcmp(output,"NF")==0) {
	printf("%s\n",output);
        
      }
      else {
	sscanf(output,"%39s %d",dest_ip,&mask);
	printf("%s:%d\n",dest_ip,mask);
	
	//Look up MAC
	macAddr = find_mac(ipte, dest_ip, mask, 2);
	printf("Look up MAC Done\n");
        
	//Recreate packet
	send_ether(Buffer, macAddr, srcAddr, Size);
	printf("Send Done\n");
	
      }
      
      
    }
    fprintf(stdout , "\nEND of ICMP Operation\n\n");
	//return NULL;
}

//void print_tcp_packet(const u_char * Buffer, int Size)
void* print_tcp_packet(void* threadarg)
{
    u_char * Buffer;
    int Size;
    
    struct thread_data *td;
    td = (struct thread_data *) threadarg;
    Buffer=td->buffer;
    Size=td->size;
    u_char* macAddr;
    char dest_ip[40];
    int mask =0;
    char output[100];
    
    print_ethr_header(Buffer);
    
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    
    iphdrlen = iph->ihl*4;
 	memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
	
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    
    fprintf(stdout , "\n\nTCP Packet Contents\n");
    
    fprintf(stdout , "\n");
    
    fprintf(stdout , "TCP Header\n");
    fprintf(stdout , "Source Port      : %u\n",ntohs(tcph->source));
    fprintf(stdout , "Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(stdout , "Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(stdout , "Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(stdout , "Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(stdout , "Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(stdout , "Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(stdout , "Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(stdout , "Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(stdout , "Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(stdout , "Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(stdout , "Window         : %d\n",ntohs(tcph->window));
    fprintf(stdout , "Checksum       : %d\n",ntohs(tcph->check));
    fprintf(stdout , "Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(stdout , "\n");
    
	//Update IP Header
    iph = print_ip_header(Buffer,Size);
    
    //Look up IP for network
    lookupIP(inet_ntoa(dest.sin_addr), tree, output);
    
    if(strcmp(output,"NF")==0) {
        printf("%s\n",output);
    } else {
      sscanf(output,"%39s %d",dest_ip, &mask);
        printf("%s:%d\n",dest_ip,mask);
    }
    
	//Look up MAC
    macAddr = find_mac(ipte, dest_ip, mask, 2);
    
    //Recreate packet
    send_ether(Buffer, macAddr, srcAddr, Size);
    
    fprintf(stdout , "\nEnd of TCP Operation\n\n");
    
    return NULL;
}

//void* print_udp_packet(void* threadarg)
void print_udp_packet(u_char * Buffer , int Size)
{
    
    char output[100];
        
    print_ethr_header(Buffer);
	
    u_char* macAddr;
    unsigned short iphdrlen;
    char dest_ip[40];
    int mask = 0;
	
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    
    iphdrlen = iph->ihl*4;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    
    fprintf(stdout , "\n\nUDP Packet Contents\n");
    
    fprintf(stdout , "\nUDP Header\n");
    fprintf(stdout , "Source Port      : %d\n" , ntohs(udph->source));
    fprintf(stdout , "Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(stdout , "UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(stdout , "UDP Checksum     : %d\n" , ntohs(udph->check));
    fprintf(stdout , "\n");
    
    //Update IP Header
    
    if(print_ip_header1(&Buffer,&Size)) {
  
        // time exceeded, to reply
        u_char ourMAC[6] = {};
        u_char rplyMAC[6] = {};
        memcpy(rplyMAC, Buffer+6, 6);
        memcpy(ourMAC, Buffer, 6);
                
        //      send_ether(Buffer, Buffer+6, ourMAC, Size);
        send_ether(Buffer, rplyMAC, ourMAC, Size);
        printf("**********************sent time exceeded msg************************\n");
        // free the memory allocated in the print_ip_header1
        free(Buffer);
        
    } else {
        
        // let kernel handle local traffic (ttl != 0)
        if(!(strcmp(inet_ntoa(dest.sin_addr),"10.10.0.1")) || !(strncmp(inet_ntoa(dest.sin_addr),"10.99", 5))) {
            ;
        } else {
	  
	  //Look up IP for network
            lookupIP(inet_ntoa(dest.sin_addr), tree, output);
	    
            if(strcmp(output,"NF")==0) {
	      printf("%s\n",output);
            } else {
	      sscanf(output,"%39s %d",dest_ip,&mask);
	      printf("%s:%d\n",dest_ip,mask);
                
	      //Look up MAC
	      macAddr = find_mac(ipte, dest_ip, mask, 2);
	      send_ether(Buffer, macAddr, srcAddr, Size);
              
            }
        }
        
        
        
    }
    
    fprintf(stdout , "\nEnd of UDP Operation\n\n");
	
}

void send_ether(u_char * Buffer,u_char* macAddr,u_char* srcAddr, int Size) {
	
    int i=0;
	
    for(i=0; i<6; i++) {
      Buffer[i] = macAddr[i];
    }
    
    for(; i<12; i++) {
      Buffer[i] = srcAddr[i];
    }
    printf("\n");
    printf("\n");
    

    pcap_inject ( handle_lan, Buffer, Size );
}
//
void print_arp_packet(u_char* Buffer, int Size) {
    
    print_ethr_header(Buffer);
    
    struct arphdr* arpheader = (struct arphdr*)(Buffer + sizeof(struct ethhdr));
    
    fprintf(stdout , "\nARP Packet Contents\n");
    
    printf("Received Packet Size: %d bytes\n", Size);
    printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
    printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
    printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");
    
    /* If is Ethernet and IPv4, print packet contents */
    if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
        printf("Sender MAC: ");
        
        for(i=0; i<6;i++)
            printf("%02X:", arpheader->sha[i]);
        
        printf("\nSender IP: ");
        
        for(i=0; i<4;i++)
            printf("%d.", arpheader->spa[i]);
        
        printf("\nTarget MAC: ");
        
        for(i=0; i<6;i++)
            printf("%02X:", arpheader->tha[i]);
        
        printf("\nTarget IP: ");
        
        for(i=0; i<4; i++)
            printf("%d.", arpheader->tpa[i]);
        
        printf("\n");
    }
    //	return NULL;
}


//Checksum function
unsigned short cksum(uint16_t *iph, int len) {

  uint16_t *ip = iph;
  uint32_t sum = 0;
  while (len > 1) {
    sum += *ip++;
    if(sum & 0x80000000) /* if high order bit set, fold */
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }
  
  /* take care of left over byte */
  if (len) sum += (uint16_t) *(uint8_t *)ip;
  
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  
  return (unsigned short) (sum ^ 0xFFFF);

}

struct iphdr *print_ip_header(u_char * Buffer, int Size) {
    
    unsigned short checkSum;
    unsigned int ttl;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    
    
    unsigned short iphdrlen;

    iphdrlen = iph->ihl * 4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    fprintf(stdout , "\n");
    fprintf(stdout , "IP Header\n");
    fprintf(stdout , "IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(stdout , "IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(stdout , "Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(stdout , "IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(stdout , "Identification    : %d\n",ntohs(iph->id));
    fprintf(stdout , "TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(stdout , "Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(stdout , "Checksum : %d\n",ntohs(iph->check));
    fprintf(stdout , "Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(stdout , "Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
    
    ttl = (unsigned int) iph->ttl;
    //printf("%d\n", ttl);
	
    
    //Check the checksum field
    if((cksum((uint16_t*)iph,((unsigned int)(iph->ihl))*4)) == 0) {
      
      //Decrement TTL
      iph->ttl = iph->ttl - 1;
        
      if (iph->ttl == 0){
	printf("dropping packet in print_ip_header\n");
        
	u_char* packet;
        
	packet = (u_char*)malloc(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
	memcpy(packet,Buffer,(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)));
	memcpy((packet+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)),(Buffer+sizeof(struct ethhdr)),sizeof(struct iphdr));
	memcpy((packet+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)+sizeof(struct iphdr)),(Buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)),8);
        
	Buffer=packet;
	iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	//icmpheader = (struct icmphdr*) (Buffer  + sizeof(struct ethhdr) + sizeof(struct iphdr));
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
            
	icmph->type = 11;
	icmph->code = 0;
            
	iph->protocol = 1;
	iph->ttl = 64;
	iph->daddr = iph->saddr;
        
        
	iph->saddr = inet_addr("10.99.0.3");   //FILL IN THE SRC ADDR
	unsigned short chkSum;
	icmph->checksum = 0;
	chkSum = cksum((uint16_t*)icmph,sizeof(struct icmphdr));
	printf("ICMP checksum in print_ip_header: %d\n",chkSum);
	icmph->checksum = chkSum;

      }
      //Make current checksum zero
      iph->check = 0;
      //Call checksum function
      checkSum = cksum((uint16_t*)iph,((unsigned int)(iph->ihl))*4);
      printf("IP checksum in print_ip_header: %d\n",checkSum);
      //Insert new checksum
      iph->check = (checkSum);
    } else {
      //Do nothing
      //Drop packet
      printf("Dropping packet\n");
    }
    
    
    //Return recomputed IP header
    return iph;
}


int print_ip_header1(u_char ** BufferRef, int *Size) {
    
    unsigned short checkSum;
    unsigned int ttl;
    int flag = 0; // assume no time out initially
    
    u_char * Buffer = (*BufferRef);
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    
    u_char* packet = NULL;
     
    unsigned short iphdrlen;
   
    iphdrlen = iph->ihl * 4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    fprintf(stdout , "\n");
    fprintf(stdout , "IP Header\n");
    fprintf(stdout , "IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(stdout , "IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(stdout , "Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(stdout , "IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(stdout , "Identification    : %d\n",ntohs(iph->id));
    fprintf(stdout , "TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(stdout , "Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(stdout , "Checksum : %d\n",ntohs(iph->check));
    fprintf(stdout , "Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(stdout , "Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
    
    ttl = (unsigned int) iph->ttl;
    //printf("%d\n", ttl);
	
    
    
	
    //Check the checksum field
    if((cksum((uint16_t*)iph,((unsigned int)(iph->ihl))*4)) == 0) {
       
      // check dest ip here
      // if dest ip is mine, check the port number(should be some invalid port number),reply destination unreachable
      if(!strcmp(inet_ntoa(dest.sin_addr), LAN_IP) || !strcmp(inet_ntoa(dest.sin_addr), LINK_IP)) {
	
	flag = 1;
	int appendSize = ((60-20-8) < (*Size-20-14-8))? (60-20-8):(*Size-20-14-8);

	packet = (u_char*)malloc(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + appendSize);

	memset(packet, 0, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + appendSize);
          
	memcpy(packet,Buffer,(sizeof(struct ethhdr) + sizeof(struct iphdr)));

	memcpy((packet+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)),(Buffer+sizeof(struct ethhdr)), appendSize);
          
	Buffer=packet;

	iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	//icmpheader = (struct icmphdr*) (Buffer  + sizeof(struct ethhdr) + sizeof(struct iphdr));
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
          
	icmph->type = 3;
	icmph->code = 3;
        
	iph->protocol = 1;
	iph->ttl = 64;
	iph->tot_len = htons(60);
	iph->id = htons(id);
	id++;
	  
	//LAN_IP
	iph->daddr = source.sin_addr.s_addr;                       
	//iph->saddr = dest.sin_addr.s_addr;   //FILL IN THE SRC ADDR
	iph->saddr = inet_addr(LAN_IP);

	unsigned short chkSum;
	icmph->checksum = 0;
	chkSum = cksum((uint16_t*)icmph,sizeof(struct icmphdr)+appendSize);
	printf("ICMP checksum in print_ip_header: %d\n",chkSum);
	icmph->checksum = chkSum;

	iph->check = 0;
	//Call checksum function
	checkSum = cksum((uint16_t*)iph,((unsigned int)(iph->ihl))*4);
	printf("IP checksum in print_ip_header: %d\n",checkSum);
	//Insert new checksum
	iph->check = (checkSum);


      } else {
	

	//Decrement TTL
	iph->ttl = iph->ttl - 1;
        
	if (iph->ttl == 0){
	
	  iph->ttl = 1;
	  
	  flag = 1;
	  
	  printf("ttl = 0\n");
            
          
	  // the size of the ip payload needed to put in the icmp msg
	  int appendSize = ((60-20-8) < (*Size-20-14-8))? (60-20-8):(*Size-20-14-8);
            
	  packet = (u_char*)malloc(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + appendSize);
	            
	  memset(packet, 0, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + appendSize);
          
	  memcpy(packet,Buffer,(sizeof(struct ethhdr) + sizeof(struct iphdr)));	  
	  
	  memcpy((packet+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)),(Buffer+sizeof(struct ethhdr)), appendSize);
          
	  Buffer=packet;
	  iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );

	  struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
          
	  icmph->type = 11;
	  icmph->code = 0;
          
	  iph->protocol = 1;
	  iph->ttl = 64;
	  iph->tot_len = htons(60);
	  iph->id = htons(id);
	  id++;
          
	  //LAN_IP
	  iph->daddr = source.sin_addr.s_addr;                       
	  iph->saddr = inet_addr(LAN_IP);
          
          
	  unsigned short chkSum;
	  icmph->checksum = 0;
	  chkSum = cksum((uint16_t*)icmph,sizeof(struct icmphdr)+appendSize);
	  printf("ICMP checksum in print_ip_header: %d\n",chkSum);
	  icmph->checksum = chkSum;
	  
	  //printf("+++++++++++++++++icmp cksum:%d+++++++++++++\n", cksum(icmph,sizeof(struct icmphdr)));
	  // printf("!!!!!!!!!!iph ihl:%d!!!!!!!!!!!!!!!!!!!\n", ((unsigned int)(iph->ihl))*4);
          
                    
	  //Make current checksum zero
	  iph->check = 0;
	  //Call checksum function
	  checkSum = cksum((uint16_t*)iph,((unsigned int)(iph->ihl))*4);
	  printf("IP checksum in print_ip_header: %d\n",checkSum);
	  //Insert new checksum
	  iph->check = (checkSum);
          
	  //printf("+++++++++++++++++ip cksum:%d+++++++++++++\n", cksum(iph,((unsigned int)(iph->ihl))*4));
          
	  fprintf(stdout , "\n");
	  fprintf(stdout , "IP Header\n");
	  fprintf(stdout , "IP Version        : %d\n",(unsigned int)iph->version);
	  fprintf(stdout , "IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	  fprintf(stdout , "Type Of Service   : %d\n",(unsigned int)iph->tos);
	  fprintf(stdout , "IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	  fprintf(stdout , "Identification    : %d\n",ntohs(iph->id));
	  fprintf(stdout , "TTL      : %d\n",(unsigned int)iph->ttl);
	  fprintf(stdout , "Protocol : %d\n",(unsigned int)iph->protocol);
	  fprintf(stdout , "Checksum : %d\n",ntohs(iph->check));
	  
	  memset(&source, 0, sizeof(source));
	  source.sin_addr.s_addr = iph->saddr;
          
	  memset(&dest, 0, sizeof(dest));
	  dest.sin_addr.s_addr = iph->daddr;
          
          
	  fprintf(stdout , "Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	  fprintf(stdout , "Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
          
            
        } else {
            
	  // ttl != 0
	  //Make current checksum zero
	  iph->check = 0;
	  //Call checksum function
	  checkSum = cksum((uint16_t*)iph,((unsigned int)(iph->ihl))*4);
	  printf("IP checksum in print_ip_header: %d\n",checkSum);
	  //Insert new checksum
	  iph->check = (checkSum);
          
        }
      }
        
    } else {
      
      // check sum error
      // Do nothing
      // Drop packet
      printf("Checksum error: Dropping packet\n");
        
    }
    
    
    if (flag == 0)
      return 0;
    else {
      *BufferRef = packet;
      *Size = 576 + 14;
      return 1;
    }
}

int print_icmp_echoreply(u_char ** BufferRef, int *Size) {
    
    unsigned short checkSum;
    unsigned int ttl;

    
    u_char * Buffer = (*BufferRef);
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    
    unsigned short iphdrlen;

    iphdrlen = iph->ihl * 4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    fprintf(stdout , "\n");
    fprintf(stdout , "IP Header\n");
    fprintf(stdout , "IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(stdout , "IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(stdout , "Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(stdout , "IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(stdout , "Identification    : %d\n",ntohs(iph->id));
    fprintf(stdout , "TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(stdout , "Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(stdout , "Checksum : %d\n",ntohs(iph->check));
    fprintf(stdout , "Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(stdout , "Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
    
    ttl = (unsigned int) iph->ttl;
	
    //Check the checksum field
    if((cksum((uint16_t*)iph,((unsigned int)(iph->ihl))*4)) == 0) {
      
      iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
      //icmpheader = (struct icmphdr*) (Buffer  + sizeof(struct ethhdr) + sizeof(struct iphdr));
      struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
        
      icmph->type = 0;
      icmph->code = 0;
      
      iph->protocol = 1;
      iph->ttl = 64;
      iph->id = htons(id);
      id++;
        

      iph->daddr = source.sin_addr.s_addr;                       
      iph->saddr = inet_addr(LAN_IP);
      
      
      unsigned short chkSum;
      icmph->checksum = 0;
      chkSum = cksum((uint16_t*)icmph,(*Size-sizeof(struct ethhdr)-sizeof(struct iphdr)));
      printf("ICMP checksum in print_ip_header: %d\n",chkSum);
      icmph->checksum = chkSum;
      
      //printf("+++++++++++++++++icmp cksum:%d+++++++++++++\n", cksum(icmph,(*Size-sizeof(struct ethhdr)-sizeof(struct iphdr))));      
      //printf("!!!!!!!!!!iph ihl:%d!!!!!!!!!!!!!!!!!!!\n", ((unsigned int)(iph->ihl))*4);
        
        
        
      //Make current checksum zero
      iph->check = 0;
        //Call checksum function
      checkSum = cksum((uint16_t*)iph,((unsigned int)(iph->ihl))*4);
      printf("IP checksum in print_ip_header: %d\n",checkSum);
      //Insert new checksum
      iph->check = (checkSum);
      
      //printf("+++++++++++++++++ip cksum:%d+++++++++++++\n", cksum(iph,((unsigned int)(iph->ihl))*4));
      
      fprintf(stdout , "\n");
      fprintf(stdout , "IP Header\n");
      fprintf(stdout , "IP Version        : %d\n",(unsigned int)iph->version);
      fprintf(stdout , "IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
      fprintf(stdout , "Type Of Service   : %d\n",(unsigned int)iph->tos);
      fprintf(stdout , "IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
      fprintf(stdout , "Identification    : %d\n",ntohs(iph->id));
      fprintf(stdout , "TTL      : %d\n",(unsigned int)iph->ttl);
      fprintf(stdout , "Protocol : %d\n",(unsigned int)iph->protocol);
      fprintf(stdout , "Checksum : %d\n",ntohs(iph->check));
      
      memset(&source, 0, sizeof(source));
      source.sin_addr.s_addr = iph->saddr;
      
      memset(&dest, 0, sizeof(dest));
      dest.sin_addr.s_addr = iph->daddr;
      
      
      fprintf(stdout , "Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
      fprintf(stdout , "Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
      
      
    } else {
      
      // check sum error
      // Do nothing
      // Drop packet
      printf("Checksum error: Dropping packet\n");
      
    }
       
    return 1;
}
