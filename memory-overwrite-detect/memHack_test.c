#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func1(void)
{
	
	char *p = malloc(16);

	char *q = calloc(1, 128);

	printf("p:%p, q:%p\n", p, q);

	p = realloc(p, 64);

	printf("p:%p\n", p);

	p = realloc(p, 32);
	
	printf("p:%p\n", p);

	free(q);

	memset(p, 1, 16);

	free(p);
}


int main(int argc, char *argv[])
{
	
	func1();

	printf("saiyn:MEM HACK\n");


	for(;;)
	{
		sleep(1);
	}

	return 0;
}
