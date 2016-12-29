#include <stdio.h>
#include "total.c"

extern counter total;
extern FILE *fp;

void ctrlc_message(int s);
void fprintToFile();

void ctrlc_message(int s){
	printf("\n\n--------------------------\n");
	printf("Stop get packet. Get signal %d.\n",s);

	strcpy(total.timeEnd,getTime());

	printf("Start Time:\t%sEnd Time:\t%s\n",total.timeStart,total.timeEnd);
	printf("ARP Packet:\t%d\n",total.pacCnt[0]);
	printf("TCP Packet:\t%d\n",total.pacCnt[2]);
	printf("UDP Packet:\t%d\n",total.pacCnt[3]);
	printf("ICMP Packet:\t%d\n", total.pacCnt[1]);
	printf("IP Packet:\t%d\n",total.IPCnt);
	printf("Unknown IP Pkt:\t%d\n",total.pacCnt[5]);
	printf("Unknown Packet:\t%d\n",total.pacCnt[6]);
	printf("Total Packet:\t%d\n",total.totalCnt);
	printf("Total Data:\t%lu\n",total.totalData);

	printf("\n--------------------------\n");

	fprintToFile();
	fclose(fp);
	exit(0);
}


void fprintToFile(){
	fprintf(fp,"\n\n--------------------------\n");
	fprintf(fp,"Start Time:\t%sEnd Time:\t%s\n",total.timeStart,total.timeEnd);
	fprintf(fp,"ARP Packet:\t%d\n",total.pacCnt[0]);
	fprintf(fp,"TCP Packet:\t%d\n",total.pacCnt[2]);
	fprintf(fp,"UDP Packet:\t%d\n",total.pacCnt[3]);
	fprintf(fp,"ICMP Packet:\t%d\n", total.pacCnt[1]);
	fprintf(fp,"IP Packet:\t%d\n",total.IPCnt);
	fprintf(fp,"Unknown IP Pkt:\t%d\n",total.pacCnt[5]);
	fprintf(fp,"Unknown Packet:\t%d\n",total.pacCnt[6]);
	fprintf(fp,"Total Packet:\t%d\n",total.totalCnt);
	fprintf(fp,"Total Data:\t%lu\n",total.totalData);
	fprintf(fp,"\n--------------------------\n");
}