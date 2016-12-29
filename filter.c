#include <stdio.h>
#include <string.h>

#define TRUE 1
#define FALSE 0
#define ALL 5


typedef struct filter{
	int packet[4];
	char saddr[50];
	char daddr[50];
}filter;


/*Set Filter -- Type of Packet*/
void setPacFilter(char opt,filter *filter){
	switch(opt){
		case 'a':
			filter->packet[0] = TRUE;
			break;
		case 'i':
			filter->packet[1] = TRUE;
			break;
		case 't':
			filter->packet[2] = TRUE;
			break;
		case 'u':
			filter->packet[3] = TRUE;
			break;
		case 'z':
			filter->packet[0] = ALL;
			break;
		}
}

/*Set Filter -- Type of Addr*/
void setAddrFilter(char opt,filter *filter,char* addr){
	switch(opt){
		case 's':
			strcpy(filter->saddr,addr);
			break;
		case 'd':
			strcpy(filter->daddr,addr);
			//printf("%s\n%s\n",filter->daddr,addr);
			break;
	}
}

/*
void testFilter(filter filter){
	int i;
	printf("test filter:\n");
	for(i=0;i<2;i++){
		printf("%d",filter.packet[i]);
	}
	printf("\n");
	for(i=0;i<3;i++){
		printf("%d",filter.segment[i]);
	}
	printf("\n");
}
Test*/