#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include "sniffer.c"
#include "helppage.c"

counter total = {"\0","\0",{0},0,0,0};
FILE *fp;

int main(int argc,char *argv[]){
	int opt;
	struct sigaction sigHandler;
	filter filter = {{0},"",""};
	/*Catch Ctrl+C*/
	sigHandler.sa_handler = ctrlc_message;
	sigemptyset(&sigHandler.sa_mask);
	sigHandler.sa_flags = 0;
	sigaction(SIGINT,&sigHandler,NULL);
	/*Stop Output Error*/
	opterr = 0;

	if(argc==1){
        printf("Values Error! -[].Input '-h' to see the help.\n");
        exit(0);
    }
	
	if((fp=fopen("record.txt","w"))== NULL){
		printf("Can't open the file.\n");
		exit(0);
	}
	
	while((opt = getopt(argc,argv,":s:d:achituz")) != -1){

		switch(opt){
			case 's':
				setAddrFilter(opt,&filter,optarg);
				//printf("%s\n",optarg);
				break;
			case 'd':
				setAddrFilter(opt,&filter,optarg);
				//printf("%s\n",optarg);
				break;
			case 'z':
			case 'a':
			case 't':
			case 'u':
			case 'i':
				setPacFilter(opt,&filter);
				break;
			/*------------------------*/
			case 'h':
				//getHelpPage();
				helpPage();
				break;
			case ':':
				printf("Need an ADDR value!\n");
			default:
				printf("Unknown option: %c\nInput '-h' to see the help.\n",optopt);
		}
	}

	getData(filter);

	return 0;
}