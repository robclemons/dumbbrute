/*
	Written By: Robbie Clemons
	email: RobClemons@gmail.com
*/
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "sha512test.h"

#define NUM_CHARS 9
#define MAX_PASS_LEN 8
#define DEFAULT_NUM_PROCESSES 2

void usage()
{
	char *usageText = "Usage of dumbbrute:\n\n  dumbbrute <filename> where filename is the file with only the hash in it\n\n  Use -p to set the number of processes to spawn:\n\n  dumbbrute -p 2 <filename>\n\n";
	printf("%s", usageText);
	
}
		
int brute(int pNum, char *salt, char *crypt, char *passchars, int numProcs)
{
	char pass[25];
	int count;
//	printf("%d\n", pNum);
	for(count = pNum; count < pow(NUM_CHARS, MAX_PASS_LEN); count += numProcs)
	{
		int total = count;	
		int passIndex = 0;
		int i;
		for(i = 1;pow(NUM_CHARS,i) < total;++i)
		{
			total -= pow(NUM_CHARS,i);
		}
		--total;

		int j;
		int tmp = total;
		for(j = i; j > 1; --j)
		{
			tmp = total / pow(NUM_CHARS,j-1);
			pass[passIndex] = passchars[tmp];
			total -= tmp * pow(NUM_CHARS, j-1);
			++passIndex;
		}
		int chrIndex = total % NUM_CHARS;
		pass[passIndex] = passchars[chrIndex];
		++passIndex;
		pass[passIndex] ='\0';
//		printf("trying: %s\n",pass);
		char *result = __sha512_crypt(pass, salt);
		if(strcmp(result, crypt) == 0)
		{
		
			printf("password: %s, it took %d hashes\n", pass, count);
			return count;
		}
	//	printf("%d\n", count);
	}
	return 0;

}
int main(int argc, const char** argv)
{
	int numProcs = DEFAULT_NUM_PROCESSES;
	if(argc == 2 && strcmp(argv[1],"test") == 0)
		test();
	else if(argc == 4 && strcmp(argv[1],"-p") == 0)
	{
		numProcs = atoi(argv[2]);
	}
	FILE *hashFile;
	hashFile = fopen(argv[argc-1],"r");
	if(errno != 0)
	{
		printf("Invalid file name\n\n");
		usage();
		exit(0);
	}
	char crypt[107];
	fscanf(hashFile, "%s", crypt);
	fclose(hashFile);
	printf("%s\n", crypt);
	char salt[20];
	if(crypt[1] == '6')
	{
		strncpy(salt,crypt, 19);
		salt[19] = "\n";
	}
	else
	{
		printf("Unsopported hash type\n");
		exit(0);
	}
	char passchars[NUM_CHARS] = "bcdmno123";
	time_t start, finish;
	start = time(NULL);
	int found = 0;
	int i;
	pid_t pid = 1;
	for(i = 1; i <= numProcs; ++i)
	{
		if(pid > 0)
		{
		pid = fork();
		if(pid == 0)
			found = brute(i, salt, crypt, passchars, numProcs);
		}
	}
	if(pid > 0)
		wait();
	if(found != 0)
	{
		finish = time(NULL);
		int time = difftime(finish, start);
		printf("It took %d seconds\n",time);
		printf("averaged %f c/s\n", (float)found / time);
		kill(0, SIGKILL);
	}
        return 0;
}
