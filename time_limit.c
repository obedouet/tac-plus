/* 		
	These functions writen by Devrim SERAL <devrim@gazi.edu.tr>

Applicable format is  : <day str><time str> [,|] <day str><time str> [,|] and so on  

The accept parameter for day str is:
SU = Sunday
MO = Monday
TU = Tuesday
WE = Wendsday
TH = Thursday
FR = Friday
SA = Saturday
WK = For week days
WD = For Week and
AL = For All days

And time str must be:
Hourminute-Hourminute  
For example it's to be -> 0000-1200 or 1600-1700 or 1600-0800

License: This code is free software; you can redistribute it and/or modify it 
under the terms of the GNU General Public License as published by the Free 
Software Foundation; either version 2, or (at your option) any later version.
		
*/	

#include"time_limit.h"
#include "tac_plus.h"

int problem=0;

int 
time_limit_process(str) 
char *str;
{
int ret=0;
char *tmp_str;

tmp_str=(char *)strtok(str,",|");
while ( tmp_str != NULL) {
	ret|=str_token_proc(tmp_str);
	tmp_str=(char *)strtok(NULL,",");
	}
return (ret); 
}

int 
str_token_proc(str)
char *str;
{
int inv=0,ret;

/* Pass space characters */ 
while (isspace(*str)) str++;

if (*str=='!') { 
		inv=1;str++; 
}

ret=process(str);

if (problem) {
	if ( debug & DEBUG_AUTHEN_FLAG )
               report(LOG_DEBUG,"Timestamp format incorrect");
	problem=0;
	return(0);
} 

if (inv) 
	ret=!ret;
return(ret);	
}


int
process(str)
char *str;
{
int count=0,ret=0,i,j,localtm;
char *head,*buf,*gec;
long sec;
struct tm *tms;

/* Pass space characters  */
while (isspace(*str)) str++;

head=str;

/* Count alphanumeric char */
while (isalpha(*str)) { 
	count++;
	str++;
}

if ( count==0 || count%2 ) { 
	problem++;
	return 0;
}

buf=(char *) s_malloc(count+1);
strncpy(buf,head,count);
gec=buf;
str_up(buf);

for(i=1;i<=(count/2);i++) {
	for (j=0;j<NUM;j++) {
                if(!strncmp(gec,week_days[j],2)) {
                        ret=ret^week_day_val[j];
                }
        }
	gec+=2;
}

/* We finished to use buffer so free it */
s_free(buf);

sec=time(0);
tms=localtime(&sec);
localtm=(tms->tm_hour)*60+tms->tm_min;
ret=( week_day_val[tms->tm_wday] & ret ) && time_calc(str,localtm);

if (ret>0) 
	return (1); 
else 
	return(0); 
}

str_up(str)
char *str;
{
  while(*str) {
	if(islower(*str)) *str=toupper(*str);
	str++;
  }
}

int 
time_calc(str,lct)
char *str;
int lct;
{
char *t1,*t2,*head;
int say1,say2,count=0;

head=str;

 while (isdigit(*head) || *head=='-') {
        count++;
	head++;	
 }

if (*str=='\0' || count!= TPL ) {
	problem++;	
	return (0);
}

  t1=(char *)  s_malloc(count);
  strncpy(t1,str,count);	/*Put str value to t1*/

  t2=(char *) strstr(t1,"-"); /* Find next time part */

if (t2==NULL) {
   s_free(t1);
   problem++;
   return(0);
}
	
*t2='\0';t2++;
	
if ( strlen(t1)<4 || strlen(t2)<4 ) {
	s_free(t1);
	problem++;
	return(0);
}
	say1=antoi(t1,2)*60+antoi(t1+2,2);
	say2=antoi(t2,2)*60+antoi(t2+2,2);

s_free(t1);

if (say1<=say2) { 
	if( (lct>=say1) && (lct<=say2) ) return(1); 
}
else {
	if( (lct>=say1) || (lct<=say2) ) return(1); 
}
return(0);

}

int 
antoi(str,n)
char *str;int n;
{
char *buf;
int ret;

  buf=(char *)  s_malloc(n);
  strncpy(buf,str,n);
  ret=atoi(buf);
  s_free(buf);

return(ret);
}
