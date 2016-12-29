#include <stdio.h>

int main(){

	FILE *fp = fopen("mac.txt","r");
	unsigned char buffer[4096];
	while(fgets(buffer,4096,fp)!=NULL){
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n",buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
		//printf("%s\n",buffer);
	}
	return 0;
}