#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <fcntl.h>
#include <netinet/in.h> 
#include <net/if.h>
#include <netinet/ip.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <arpa/inet.h>

#include "filter.c"
#include "ctrlc.c"

#define IFR_NAME "eth0"
#define BUF_SIZE 2048

enum packet_type{ARP,ICMP,TCP,UDP,IPv6,IPUnknown,Unknown};
char typeString[10][15]={"ARP","ICMP","TCP","UDP","IPv6","IPUnknown","Unknown"};
extern counter total;
extern FILE *fp;

typedef struct arphdr{
	uint16_t hwtype;		/*hardware type*/
	uint16_t protocol;		/*protocol type*/
	uint8_t hd_addrlen;		/*hardware address length*/
	uint8_t ip_addrlen;		/*protocal address length*/
	uint16_t accode;		/*action code*/
	uint8_t hd_saddr[6];	/*hardware address - source*/
	uint8_t ip_saddr[4];	/*ip address - source*/
	uint8_t hd_daddr[6];	/*hardware address - destination*/
	uint8_t ip_daddr[4];	/*ip address - destination*/
}arphdr;


typedef struct pacStruct{
	unsigned char s_mac[ETH_ALEN];
	unsigned char d_mac[ETH_ALEN];
	char s_ip[50];
	char d_ip[50];
	int data;
	int type;
}pktstr;


int createSocket(const int protocol);
struct ifreq setIFR(int fd);
void printMACAddr(struct ethhdr *eth);
void printInfoIP(struct iphdr *ip);
void printInfoARP(struct arphdr *arp);
void getData(struct filter filter);
void closeSocket(int fd);
pktstr parseModule(char* buff,int data);
void sniffModule(pktstr pktstr,filter filter);
void printInfo(pktstr pktstr);
void totalModule(int type,int data);
void findMAC(unsigned char* saddr,unsigned char* daddr);

int createSocket(const int protocal){
	int fd;
	fd = socket(PF_PACKET,SOCK_RAW,htons(protocal));
	if(-1 == fd){
        printf("Create socket error!\n");
        return -1;
    }
    return fd;
}


void closeSocket(int fd){
	close(fd);
}


struct ifreq setIFR(int fd){
	struct ifreq ifr;
	strcpy(ifr.ifr_name, IFR_NAME);
    ifr.ifr_flags |= IFF_PROMISC;
    if(-1 == ioctl(fd,SIOCGIFINDEX,&ifr)){
        printf("Ioctl Error!\n");
        close(fd);
        exit(0);
    }
    return ifr;
}

/*Get Data*/
void getData(struct filter filter){
	int fd;
	char buff[BUF_SIZE];
	struct ifreq ifr;
	struct sockaddr_ll sll;
	struct ethhdr *eth;
	pktstr pktstr;
	
	fd = createSocket(ETH_P_ALL);
	sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifr.ifr_ifindex;

	strcpy(total.timeStart,getTime());

	while(1){
		int data;

		data = recv(fd,buff,BUF_SIZE,0);

		//printMACAddr(eth);

		pktstr = parseModule(buff,data);
		sniffModule(pktstr,filter);
	}
}


pktstr parseModule(char* buff,int data){
	int signal,i;
	pktstr pktstr = {"","","","",0,0};
	struct ethhdr *eth;
	struct in_addr addr;
	enum packet_type ptype;
	pktstr.data = data;
	eth = (struct ethhdr *)buff;
	for(i=0;i<ETH_ALEN;i++){
		pktstr.d_mac[i] = eth->h_dest[i];
		pktstr.s_mac[i] = eth->h_source[i];
	}
	signal = *(buff+13);

	if(0 == signal){

			struct iphdr *ip;
        	ip = (struct iphdr *)(buff+14);
        	addr.s_addr=ip->daddr;
        	strcpy(pktstr.d_ip,inet_ntoa(addr));
        	addr.s_addr=ip->saddr;
        	strcpy(pktstr.s_ip,inet_ntoa(addr));

        	switch((int)ip->protocol){
    			case 1:
    				ptype = ICMP;
        			break;
    			case 6:
    				ptype = TCP;
    				break;
    			case 17:
    				ptype = UDP;
        			break;
    			default:
    				ptype = IPUnknown;
    		}
    }
    else if(6 == signal){
    	struct arphdr *arp;
    	int i;
    	char sip[20]={"\0"},dip[20]={"\0"},str[10];
    	arp = (struct arphdr *)(buff+14);

    	for(i=0;i<4;i++){
    		sprintf(str,"%d",arp->ip_saddr[i]);
    		strcat(sip,str);
    		strcat(sip,".");
    		sprintf(str,"%d",arp->ip_daddr[i]);
    		strcat(dip,str);
    		strcat(dip,".");
    	}
    	strncpy(pktstr.s_ip,sip,strlen(sip)-1);
    	strncpy(pktstr.d_ip,dip,strlen(sip)-1);
    	ptype = ARP;
	}
	else if(221 == signal){
		ptype = IPv6;
	}
	else{
		ptype = Unknown;
	}
	pktstr.type = ptype;
	//printf("test:%s %s %s %s %d %d\n",pktstr.s_mac,pktstr.d_mac,pktstr.s_ip,pktstr.d_ip,pktstr.data,pktstr.type);
	return pktstr;
}


void sniffModule(pktstr pktstr,filter filter){
	//printf("test1:%s %s\n",filter.saddr,pktstr.s_ip);
	//printf("test2:%s %s\n",filter.daddr,pktstr.d_ip);
	if(filter.packet[pktstr.type] == TRUE || filter.packet[0] == ALL || strcmp(filter.daddr,"\0")!=0 || strcmp(filter.saddr,"\0")!=0){
		// printf("test:%s %s\n",filter.saddr,pktstr.s_ip);
		// printf("test:%s %s\n",filter.daddr,pktstr.d_ip);
		if( (strcmp(filter.saddr,"") == 0 || strcmp(filter.saddr,pktstr.s_ip) == 0) && (strcmp(filter.daddr,"\0") == 0 || strcmp(filter.daddr,pktstr.d_ip) == 0)){
			printInfo(pktstr);
			totalModule(pktstr.type,pktstr.data);
			findMAC(pktstr.s_mac,pktstr.d_mac);
			printf("Done!\n");
		}
	}
}


void findMAC(unsigned char* saddr,unsigned char* daddr){
	FILE *record,*append;
	unsigned char buffer[BUF_SIZE];
	unsigned char s[50],d[50];
	int i,flag = 0;
	record = fopen("mac.txt","r");
	sprintf(s,"%02x:%02x:%02x:%02x:%02x:%02x",saddr[0],saddr[1],saddr[2],saddr[3],saddr[4],saddr[5]);
	sprintf(d,"%02x:%02x:%02x:%02x:%02x:%02x",daddr[0],daddr[1],daddr[2],daddr[3],daddr[4],daddr[5]);
	//printf("Test1:%s\n",s);
	while(!feof(record)){
		fscanf(record,"%s\n",buffer);
		//printf("Test2:%s\n",buffer);
		if(strcmp(buffer,s) == 0 || strcmp(buffer,d) == 0){
			flag = TRUE;
			break;
		}
	}
	fclose(record);
	if(flag != TRUE){
		append = fopen("mac.txt","a+");
		if(strcmp(d,s) == 0)
			fprintf(append,"%s\n",s);
		else
			fprintf(append,"%s\n%s\n",s,d);
		fclose(append);
	}
	//printf("test %s %s\n",s,d);
}


void totalModule(int type,int data){
	total.pacCnt[type]++;
	total.totalCnt++;
	total.totalData += data;
	if(type == 1 || type == 2 || type == 3 || type == 5)total.IPCnt++;
}


void printInfo(pktstr pktstr){
	printf("\n--------------------------\nRecv %d bytes. \n",pktstr.data);
	printf("Get %s packet.\n",typeString[pktstr.type]);
	printf("Dest MAC addr:\t%02x:%02x:%02x:%02x:%02x:%02x\n",pktstr.d_mac[0],pktstr.d_mac[1],pktstr.d_mac[2],pktstr.d_mac[3],pktstr.d_mac[4],pktstr.d_mac[5]);
    printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",pktstr.s_mac[0],pktstr.s_mac[1],pktstr.s_mac[2],pktstr.s_mac[3],pktstr.s_mac[4],pktstr.s_mac[5]);
    printf("Dest IP addr:\t%s\n",pktstr.d_ip);
    printf("Source IP addr:\t%s\n",pktstr.s_ip);

    fprintf(fp,"\n--------------------------\nRecv %d bytes. \n",pktstr.data);
    fprintf(fp,"Get %s packet.\n",typeString[pktstr.type]);
    fprintf(fp,"Dest MAC addr:\t%02x:%02x:%02x:%02x:%02x:%02x\n",pktstr.d_mac[0],pktstr.d_mac[1],pktstr.d_mac[2],pktstr.d_mac[3],pktstr.d_mac[4],pktstr.d_mac[5]);
    fprintf(fp,"Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",pktstr.s_mac[0],pktstr.s_mac[1],pktstr.s_mac[2],pktstr.s_mac[3],pktstr.s_mac[4],pktstr.s_mac[5]);
    fprintf(fp,"Dest IP addr:\t%s\n",pktstr.d_ip);
    fprintf(fp,"Source IP addr:\t%s\n",pktstr.s_ip);
}

/*Print MAC Info*/
void printMACAddr(struct ethhdr *eth){
	printf("Dest MAC addr:\t%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    fprintf(fp,"Dest MAC addr:\t%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    fprintf(fp,"Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
}

/*Print IP Info*/
void printInfoIP(struct iphdr *ip){
	struct in_addr addr;
    addr.s_addr=ip->daddr; 
	printf("Dest IP addr:\t%s\n",inet_ntoa(addr));
	fprintf(fp,"Dest IP addr:\t%s\n",inet_ntoa(addr));
	addr.s_addr=ip->saddr;
	printf("Source IP addr:\t%s\n",inet_ntoa(addr));
	fprintf(fp,"Source IP addr:\t%s\n",inet_ntoa(addr));
}

/*Print ARP Info*/
void printInfoARP(struct arphdr *arp){
    printf("Dest IP addr:\t%d.%d.%d.%d\n",arp->ip_daddr[0],arp->ip_daddr[1],arp->ip_daddr[2],arp->ip_daddr[3]);
    fprintf(fp,"Dest IP addr:\t%d.%d.%d.%d\n",arp->ip_daddr[0],arp->ip_daddr[1],arp->ip_daddr[2],arp->ip_daddr[3]);
	printf("Source IP addr:\t%d.%d.%d.%d\n",arp->ip_saddr[0],arp->ip_saddr[1],arp->ip_saddr[2],arp->ip_saddr[3]);
	fprintf(fp,"Source IP addr:\t%d.%d.%d.%d\n",arp->ip_saddr[0],arp->ip_saddr[1],arp->ip_saddr[2],arp->ip_saddr[3]);
}