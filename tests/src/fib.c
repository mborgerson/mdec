#include <stdio.h>
unsigned int fib(unsigned int n)
{
	unsigned int t[2];
	t[0] = 0;
	t[1] = 1;
	for (int i = 0; i < n; i++) {
		unsigned int x = t[0] + t[1];
		t[0] = t[1];
		t[1] = x;
	}
	return t[0];
}

int main(int argc, char *argv[])
{
	unsigned int n;
	if ((argc > 1) && (sscanf(argv[1], "%u", &n) == 1)) {
		printf("%u\n", fib(n));
		return 0;
	} else {
		return 1;
	}
}