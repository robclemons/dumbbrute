/*	Written By: Robbie Clemons <RobClemons@gmail.com>

	Copyright 2010 Robbie Clemons


    This file is part of dumbbrute.

    dumbbrute is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    dumbbrute is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with dumbbrute.  If not, see <http://www.gnu.org/licenses/>.*/
    
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include "sha512test.h"

#define MAX_PASS_LEN 8
#define MAX_THREADS 129

int found = 0; //set to 1 when password is found
int passwordNum = 0;//stores the number corresponding to the hashes password

struct args
{
	char charset[64];
	int charsetLen;
	char crypt[107];
	char salt[20];
	int pNum;
	int numProcs;
};

void usage()
{
	char *usageText = "Usage of dumbbrute:\n\n  dumbbrute -t <# threads> <filename>\n\n  <filename> is the file with only the hash in it\n  <# threads> is the number of threads you want to create\n\n  The -t arguement folowed by an integer is required.\n\n  example:\n\n  dumbbrute -t 4 ./myhash\n\n";
	printf("%s", usageText);
	
}

int getCharset(char charset[64])
{
	FILE *charsetFile;
	charsetFile = fopen("charset","r");
	if(errno != 0)
	{
		printf("charset file is missing\n");
		exit(0);
	}
	fscanf(charsetFile, "%s", charset);
	fclose(charsetFile);
	return strlen(charset);
}	
		
/********************************************
brute is the function that each thread executes
it accepts an args structure and modifies the gloabal
variables "found" and "passwordNum" if it finds the original password
*********************************************/
void* brute(void *myArgs)
{
	struct args *pArgs;
	pArgs = (struct args *)myArgs;
	char pass[25];
	int count;
	for(count = pArgs->pNum; count < pow(pArgs->charsetLen, MAX_PASS_LEN); count += pArgs->numProcs)
	{
		if(!found)
		{
			int total = count;	
			int passIndex = 0;
			int i;
			for(i = 1;pow(pArgs->charsetLen,i) < total;++i)
			{
				total -= pow(pArgs->charsetLen,i);
			}
			--total;

			int j;
			int tmp = total;
			for(j = i; j > 1; --j)
			{
				tmp = total / pow(pArgs->charsetLen,j-1);
				pass[passIndex] = pArgs->charset[tmp];
				total -= tmp * pow(pArgs->charsetLen, j-1);
				++passIndex;
			}
			int chrIndex = total % pArgs->charsetLen;
			pass[passIndex] = pArgs->charset[chrIndex];
			++passIndex;
			pass[passIndex] ='\0';
			char *result = __sha512_crypt(pass, pArgs->salt);
			if(strcmp(result, pArgs->crypt) == 0)
			{
				passwordNum = count;
				found = 1;
				printf("password: %s, it took %d hashes\n", pass, count);

			}
		}
		else
			pthread_exit(NULL);
	}


}
int main(int argc, const char** argv)
{
	struct args pArgs;
	/********************************************
	Get file and user inputs and do a little bit of validation
	*********************************************/
	if(argc == 2 && strcmp(argv[1],"test") == 0)
		test();
	
	if(strcmp(argv[1], "-t") != 0)
	{
		printf("Invalid arguements\n\n");
		usage();
		exit(0);
	}
	
	pArgs.numProcs = atoi(argv[2]);
	if(pArgs.numProcs <= 0)
	{
		printf("Invalid number of threads\n\n");
		usage();
		exit(0);
	}

	FILE *hashFile;
	hashFile = fopen(argv[argc-1],"r");
	if(errno != 0)
	{
		printf("Invalid file name\n\n");
		usage();
		exit(0);
	}
	
	fscanf(hashFile, "%s", pArgs.crypt);
	fclose(hashFile);

	if(pArgs.crypt[1] == '6')
	{
		strncpy(pArgs.salt,pArgs.crypt, 19);
		pArgs.salt[19] = "\n";
	}
	else
	{
		printf("Unsopported hash type\n");
		exit(0);
	}
	pArgs.charsetLen = getCharset(pArgs.charset);
	
	/*******************************************************
	Prepare and launch threads
	*******************************************************/
	time_t start, finish;
	start = time(NULL);
	int failed = 0;
	int i;
	pthread_t threadID[MAX_THREADS];
	struct args threadArgs[MAX_THREADS];
	for(i = 1; i <= pArgs.numProcs; ++i)
	{
		threadArgs[i] = pArgs;
		threadArgs[i].pNum = i;
		failed = pthread_create(&threadID[i], NULL, brute, (void*)&threadArgs[i]);
		if(failed)
		{
			printf("Failed to create thread, error %d\n", failed);
			exit(0);
		}
	}
	
	/*************************************************
	Join child threads to parent thread so that main
	waits until all the children have exited
	*************************************************/
	for(i = 1; i <= pArgs.numProcs; ++i)
	{
		
		failed = pthread_join(threadID[i], NULL);
		if(failed)
		{
			printf("Failed to join thread, error %d\n", failed);
			exit(0);
		}

	}
	
	if(found)
	{
		finish = time(NULL);
		int time = difftime(finish, start);
		printf("It took %d seconds\n",time);
		printf("averaged %f c/s\n", (float)passwordNum / time);

	}
        return 0;
}
