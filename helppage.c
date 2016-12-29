#include <stdio.h>

void helpPage(){
	printf("-z\t\tGet all packets.\n");
	printf("-i\t\tGet ICMP packets.\n");
	printf("-t\t\tGet TCP packets.\n");
	printf("-u\t\tGet UDP packets.\n");
	printf("-a\t\tGet ARP packets.\n");
}