#include <sys/time.h>  
#include <time.h>
#include <stdio.h>


typedef struct Counter{
	char timeStart[30];
	char timeEnd[30];
	int pacCnt[7];
	int totalCnt;
	int IPCnt;
	unsigned long int totalData;
}counter;


char* getTime(){
	char* systime;
	time_t timep;
	time (&timep);
	systime = asctime(gmtime(&timep));
	return systime;
}


