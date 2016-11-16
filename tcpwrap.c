/* 
   This function  use for check access control rules from hosts.deny and
   hosts.access file. 
   Writen by Devrim SERAL<devrim@gazi.edu.tr>. This file protected by 
   GNU Copyright agreement. 
*/
#ifdef TCPWRAPPER
#include <tcpd.h>
#include "tac_plus.h"

int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;


int
check_from_wrap(datap)
struct identity *datap;
{
    struct request_info req;

    request_init(&req, RQ_DAEMON,TACNAME,RQ_CLIENT_ADDR,datap->NAS_name , NULL);
    fromhost(&req); /* validate client host info */
    if (!hosts_access(&req))
      {
        if (debug & DEBUG_AUTHEN_FLAG)
		report(LOG_DEBUG, "Access denied for NAS=%s",datap->NAS_name);
        send_authen_error("You are not allowed to access here");
        refuse(&req); /* If connection is not allowed, clean up and exit. */
        return 0;
      } 
    
    if (debug & DEBUG_AUTHEN_FLAG )
                report(LOG_DEBUG, "Access permited for NAS=%s",datap->NAS_name);
return 1;     

}
#endif /* TCPWRAPPER */
