#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "sha512test.h"

#define NUM_CHARS 7
#define NUM_PROCESSES 2
int brute(int pNum, char *salt, char *crypt, char *passchars)
{
	char pass[25];
	int count;
	for(count = pNum; count < 100842; count += NUM_PROCESSES)
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
	//	printf("trying: %s\n",pass);
		char *result = __sha512_crypt(pass, salt);
		if(strcmp(result, crypt) == 0)
		{
		
			printf("password: %s, it took %d hashes\n", pass, count);
			return count;
		}
	//	printf("%d\n", count);
	}

}
int main(int argc, const char** argv)
{
	if(argc == 2 && strcmp(argv[1],"test") == 0)
		test();
	char *crypt = "$6$Y72m9KTGYlKZl6zA$S4.P9s8hkiUflpkZoGpjikGvvOLSV7iFf5DEuqMHZobaAB/lvz4cYl5JyEK2aB4k6Xu/5s0NNOaXa1ua6wqMc1";
	char *salt = "$6$Y72m9KTGYlKZl6zA";
	char passchars[NUM_CHARS] = "bcdo123";
	time_t start, finish;
	start = time(NULL);
	int found = 0;
	int i;
	pid_t pid;
	for(i = 1; i <= NUM_PROCESSES; ++i)
	{
		pid = fork();
		if(pid == 0)
			found = brute(i, salt, crypt, passchars);
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
