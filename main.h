#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>


#define DEBUG(x, args...)            \
	{                                \
		if ((x) <= verbose)          \
			fprintf(stderr, ##args); \
	}

extern int verbose;

typedef enum { OPENSSL = 0, WOLFSSL } TARGET;

bool is_running_on_device(void);

#endif // MAIN_H
