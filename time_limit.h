#include<stdlib.h>
#include<ctype.h>
#include<stdio.h>
#include<time.h>
#include<string.h>
#define NUM 10
#define TPL  9 /* time part len */

/*Global variables */
static char* week_days[]={"SU","MO","TU","WE","TH","FR","SA","WK","WD","AL"};
static long week_day_val[]={1,2,4,8,16,32,64,62,65,127};

extern int time_limit_process();
