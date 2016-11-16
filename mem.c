/*
 * Memory management func
 *
 * Simples func to handle correctly memory alloc
 * Created by Olivier BEDOUET 2009/12/7
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/syslog.h>

#define MEM_DEBUG_FILE "/tmp/mem_stats.log"

extern void report(int priority, char *fmt,...);

static int n_malloc_call=0;	/* Number of s_malloc call */
static int n_free_call=0;	/* Number of s_free call */
static int n_bytes_alloc=0;	/* Total bytes allocated */

void *s_malloc(size_t size)
{
	n_malloc_call++;
	if (size > 0)
	{
		n_bytes_alloc=n_bytes_alloc+size;
		return malloc(size);
	}
	else
		return 0;
}

void s_free(void *ptr)
{
	n_free_call++;
	if (ptr != NULL)
	{
		free(ptr);
	}
}

void s_sum(void)
{
	FILE *f_log;

	report(LOG_INFO,"Total bytes allocated: %d", n_bytes_alloc);
	report(LOG_INFO,"Total malloc() calls: %d", n_malloc_call);
	report(LOG_INFO,"Total free() calls: %d", n_free_call);

	if ((f_log=fopen(MEM_DEBUG_FILE,"a+"))!=NULL)
	{
		fprintf(f_log,"Total bytes allocated: %d\n", n_bytes_alloc);
		fprintf(f_log,"Total malloc() calls: %d\n", n_malloc_call);
		fprintf(f_log,"Total free() calls: %d\n", n_free_call);
		fclose(f_log);
	}
}

