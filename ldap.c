/*
     Verify that this user/password is valid per a database LDAP server
     Return 1 if verified, 0 otherwise.
     
     Format of connection string (look like internet URL):

       ldap://LDAP-hostname
     
     -------------------------------------------------------
     patrick.harpes@tudor.lu            http://www.santel.lu
                                        http://www.tudor.lu
     


     Dependencies: You need to get the OpenLDAP libraries
                   from http://www.openldap.org
 
      License: tac_ldap is free software; you can redistribute it
               and/or modify it under the terms of the GNU General Public License
               as published by the Free Software Foundation; either version 2,
               or (at your option) any later version.
--------------------------------------------------------------------------
				Changes:
 Ok i am back again..:)
 I changed lot of thing.. First off all i add port feature to ldap string.
 And also add more check for buffer overflows.

Connect format would be:
       ldap://LDAP-hostname:100

Port name isn't required.. I would like to change format with : 
       ldap://LDAP-hostname:100/dn_for_user&dn_for_passwd

 devrim seral <devrim@gazi.edu.tr> 

--------------------------------------------------------------------------
Changes by Olivier BEDOUET: 2009/11/09
 - does not handle DN, so a dirty patch (built-in DN) was added
 - memory not freed

Todo:
 - get the DN from configuration file
--------------------------------------------------------------------------
Changes by Olivier BEDOUET: 2010/01/05
 - DN is now read from the config like this
ldap://ldap-server:port/dn
Note: port and DN are optional.
 - a default DN can be configured
 - BUG: the length of the password was not correctly checked which resulted
that every request get Successful depending of the password
 - memory should be freed correctly (I hope :))

Todo:
 - get the search string from configuration file
--------------------------------------------------------------------------
Changes by Olivier BEDOUET: 2010/01/07
 - BUG: did not check if ldapServer is NULL
 - Modified the check of parse results: stop if ldapServer is NULL or length 
is < 4 caracters.
 - Added a define for the LDAP search string

Known bugs:
 - ldap_verify return 1 on failure and 0 on success which is not the
same as other auth func
 - WARNING: the debug mode display the user's password in clear !
--------------------------------------------------------------------------
Changes by Olivier BEDOUET: 2010/2/22
 - Removed ldap.h include
 - Added LDAP_C #define
--------------------------------------------------------------------------
Changes by Olivier BEDOUET: 2015/09/17
 - Added TLS support

*/ 

#define LDAP_C

#if defined(USE_LDAP)
#include <stdio.h>
#include <string.h>
#include <lber.h>
#include <ldap.h>
#include <ldap_cdefs.h>

#include "tac_plus.h"
/* Modified by Olivier BEDOUET */
/*#include "ldap.h"*/

/* Here you can define a default DN */
#define DEFAULT_DN "c=com"

/* Here you can define the search string */
#define SEARCH_LDAP "cn=%s"

int
ldap_verify(user, users_passwd, str_conn)
char *user, *users_passwd;      /* Username and gived password   */
char *str_conn;                 /* String connection to database */
{
  char *buf=NULL;
  char *ldap_str;
  char *ldapServer=NULL;
  char *ldap_port=NULL;
  char *ldap_dn=NULL;
  char *dn;
  char *filter;
  char *attr=NULL;
  LDAP *ld;
  int port;
  int err;
  int i;
  int ldap_Init=0;
  LDAPMessage *msg;
  LDAPMessage *entry;

  /* Don't allow null username and passwd */ 
  /* if ( *user == '0' || *users_passwd == '0' ) return (1); Olivier BEDOUET: buggy check */
  /* Added by Olivier BEDOUET 2010/01/05 */
  if (user==NULL || strlen(user)==0) return 1;
  if (users_passwd==NULL || strlen(users_passwd)==0) return (1);

  /* Olivier BEDOUET: Warning, the following report log the password in clear */
  if ( debug & DEBUG_AUTHEN_FLAG ) 
    report(LOG_DEBUG, "In ldap_verify: given parms: str_conn=%s user=%s pass=%s", str_conn, user, users_passwd);

  ldap_str=(char *) s_malloc(strlen(str_conn)+1);
  if (ldap_str == NULL ){
        report(LOG_ERR, "Error can't allocate memory");
        return(1);
  }
  strcpy(ldap_str,str_conn);

  /** -------- REMOVED BY Olivier BEDOUET
  buf=(char *) s_malloc(strlen(str_conn)+1);
  if (buf == NULL ){ 
	report(LOG_DEBUG, "Error can't allocate memory");
        return(1);
  }
  
  strcpy(buf,str_conn);
  ldapServer=strstr(buf, "://");
  
  if(ldapServer == NULL && strlen(ldapServer) <4 ) {
	if (debug) {
		report(LOG_DEBUG, "Error parse ldap server");
		return(1);
	}
  } 
  
 ldapServer=ldapServer+3;

 ldap_port=(char *)strstr(ldapServer, ":");

 if (ldap_port != NULL ) {
		*ldap_port='\0';
		port=atoi(++ldap_port);
 } else {
	port = LDAP_PORT;
 }
   ---------- END OF REMOVED */

 for (i=0 ; i < strlen(ldap_str); i++)
 {
   switch(ldap_str[i])
   {
     case ':':
       /* ldap_port or ldap:// */
       if (ldapServer == NULL)
       {
         /* We are in the ldap:// string */
         ldap_Init++;
         continue;
       }
       if (ldap_port == NULL)
       {
         /* Next is ldap_port */
         *buf='\0'; /* End of ldapServer string */
         ldap_port=(char *) s_malloc(strlen(ldap_str)-i+1);
         buf=ldap_port;
         continue;
       }
	if (debug) {
	  report(LOG_DEBUG, "Error parse ldap server, unexpected ':'");
	  return(1);
	}
      break; /* ':' */
     case '/':
      if (ldapServer == NULL)
       {
         if(ldap_Init == 1)
         {
           /* We are still in the ldap:// string */
           ldap_Init++;
           continue;
         }

	 /* Suppose that ldap_server string will follow */
         ldapServer=(char *) s_malloc(strlen(ldap_str)-i+1);
         buf=ldapServer;
         continue;
       }
       if (ldap_dn == NULL)
       {
         /* DN */
         if (buf!=NULL)
           *buf='\0';
         ldap_dn=(char *) s_malloc(strlen(ldap_str)-i+1);
         buf=ldap_dn;
         continue;
       }
	if (debug) {
	  report(LOG_DEBUG, "Error parse ldap server, unexpected '/'");
          if (ldap_dn) s_free(ldap_dn);
          if (ldap_port) s_free(ldap_port);
          if (ldapServer) s_free(ldapServer);
          if (ldap_str) s_free(ldap_str);
	  return(1);
	}
      break; /* '/' */
     default:
      if (buf != NULL)
      {
        *buf++=ldap_str[i];
      }
      break;
   }
 }
 if (buf!=NULL)
 {
   *buf='\0';
   if (debug)
   {
     report(LOG_DEBUG, "ldap server parsing results:");
     if (ldapServer) report(LOG_DEBUG, "ldap_Server=%s",ldapServer);
     if (ldap_port) report(LOG_DEBUG, "ldap_port=%s",ldap_port);
     if (ldap_dn) report(LOG_DEBUG, "ldap_dn=%s",ldap_dn);
   }
 }
 else
 {
    /* Failed */
    if (debug) {
      report(LOG_DEBUG, "Error parse ldap server, found:");
    }
    if (ldapServer)
    {
       report(LOG_DEBUG, "ldap_Server=%s",ldapServer);
       s_free(ldapServer);
    }
    if (ldap_port)
    {
       report(LOG_DEBUG, "ldap_port=%s",ldap_port);
       s_free(ldap_port);
    }
    if (ldap_dn)
    {
       report(LOG_DEBUG, "ldap_dn=%s",ldap_dn);
       s_free(ldap_dn);
    }
    if (ldap_str)
    {
       report(LOG_DEBUG, "ldap_str=%s",ldap_str);
       s_free(ldap_str);
    }
    return(1);
 }

 /* Make a check */
 /*if (ldapServer != NULL && strlen(ldapServer)<4)*/
 if (ldapServer == NULL || strlen(ldapServer)<4) /* Modified by Olivier BEDOUET 2010/01/07 */
 {
    if (debug) 
      report(LOG_DEBUG, "Error parse ldap server");
    if (ldapServer) s_free(ldapServer);
    if (ldap_port) s_free(ldap_port);
    if (ldap_dn) s_free(ldap_dn);
    if (ldap_str) s_free(ldap_str);
    return(1);
 }

 /* Apply the default LDAP DN */
 if (ldap_dn == NULL)
  ldap_dn=DEFAULT_DN;
 
 /* Get the LDAP port if parser successful */
 if (ldap_port != NULL ) {
   port=atoi(ldap_port);
 } else {
   port = LDAP_PORT;
 }
 
 if ( debug & DEBUG_AUTHEN_FLAG ) 
  report(LOG_DEBUG, "In verify_ldap : Before ldap_init : ldapserver = %s port= %d user=%s pass=%s", ldapServer, port, user, users_passwd);


  if( (ld = ldap_init(ldapServer, port)) == NULL)
    {
      report(LOG_DEBUG, "Unable to connect to LDAP server:%s port:%d",ldapServer, port);
      if (ldapServer) s_free(ldapServer);
      if (ldap_port) s_free(ldap_port);
      if (ldap_str) s_free(ldap_str);
      if (ldap_dn && strcmp(ldap_dn, DEFAULT_DN)!=0) s_free(ldap_dn);
      return 1;
    }
   else
    {
      if ( debug & DEBUG_AUTHEN_FLAG ) 
       report(LOG_DEBUG, "ldap_init succedeed!");
    }

  if (!ldap_tls_inplace(ld))
  {
    if (ldap_start_tls_s(ld, NULL, NULL)==LDAP_SUCCESS)
    {
       if ( debug & DEBUG_AUTHEN_FLAG )
         report(LOG_DEBUG, "ldap_start_tls succedeed!");
    }
    else
    {
       if ( debug & DEBUG_AUTHEN_FLAG )
         report(LOG_DEBUG, "ldap_start_tls failed!");
    }
  }
  else
  {
     if ( debug & DEBUG_AUTHEN_FLAG )
       report(LOG_DEBUG, "TLS already active!");
  }

  /* Added by Olivier BEDOUET 
   * 2009/11/09
   * Perform a search to get the complete DN for user
   */
  filter=(char *) s_malloc(strlen(user)+5);
  sprintf(filter,SEARCH_LDAP,user);

  if ( debug & DEBUG_AUTHEN_FLAG ) 
    report(LOG_DEBUG, "In ldap_verify: ldap_search parms: ldap_dn=%s filter=%s ", ldap_dn, filter);

  err=ldap_search_s(ld, ldap_dn, LDAP_SCOPE_SUBTREE, filter, &attr, 0, &msg);
   if (err <0)
   {
        if ( debug & DEBUG_AUTHEN_FLAG ) 
          report(LOG_DEBUG,"Error while search : %d %s",err, ldap_err2string(err) );
        if (ldapServer) s_free(ldapServer);
        if (ldap_port) s_free(ldap_port);
        if (ldap_port) s_free(ldap_port);
        if (ldap_str) s_free(ldap_str);
        if (ldap_dn && strcmp(ldap_dn, DEFAULT_DN)!=0) s_free(ldap_dn);
	s_free(filter);
	return 1;
   }
   else
   {
     if ( debug & DEBUG_AUTHEN_FLAG ) 
     {
       report(LOG_DEBUG,"ldap_search succedeed!");
       report(LOG_DEBUG,"The number of entries returned was %d", ldap_count_entries(ld, msg));
     }
   }
   if (ldapServer) s_free(ldapServer);
   if (ldap_port) s_free(ldap_port);
   if (ldap_str) s_free(ldap_str);
   if (ldap_dn && strcmp(ldap_dn, DEFAULT_DN)!=0) s_free(ldap_dn);
   if (filter) s_free(filter);

   if (ldap_count_entries(ld, msg) == 0)
   {
     /* The LDAP search failed */
     return 1;
   }

  /* Added by Olivier BEDOUET 2009/11/10
   * Check the result
   */
  for(entry = ldap_first_entry(ld, msg); entry != NULL; entry = ldap_next_entry(ld, entry))
   {
      if((dn = ldap_get_dn(ld, entry)) != NULL)
      {
        if ( debug & DEBUG_AUTHEN_FLAG )
          report(LOG_DEBUG,"Returned dn: %s", dn);
        /*ldap_memfree(dn);*/
      }
   }

  /* Clean up */
  ldap_msgfree(msg);

  /* Added by Olivier BEDOUET 
   * 2009/11/09
   * For debug purpore: manual method to build the DN 
   */
  /*
  dn=(char *) s_malloc(strlen(DEFAULT_DN)+strlen(user)+6);
  if (dn == NULL ){
        report(LOG_DEBUG, "Error can't allocate memory");
        return(1);
  }
  sprintf(dn,"uid=%s,%s",user,DEFAULT_DN);
  */

  /* Added by Olivier BEDOUET 09/11/09 
   * For debug purpose
   */
 if ( debug & DEBUG_AUTHEN_FLAG ) 
  report(LOG_DEBUG, "ldap dn=%s", dn);
  
  /* Modified by Olivier BEDOUET 2009/11/09 
   * Do the ldap_bind
   */
  /*err=ldap_simple_bind_s(ld, user, users_passwd);*/
  err=ldap_simple_bind_s(ld, dn, users_passwd);
  
  /*if(err != LDAP_SUCCESS) */
  if(err != 0) /* Modified by Olivier BEDOUET 2010/01/05 */
    {
      if ( debug & DEBUG_AUTHEN_FLAG ) 
      	report(LOG_DEBUG,"Error while bind : %d %s",err, ldap_err2string(err) );
      ldap_unbind_s(ld);  /* Added by Olivier BEDOUET 2010/01/05 */

      /* Added by Olivier BEDOUET 2009/11/09 */
      s_free(dn);
      return 1;
    }         
  else
    {
      /* Success */
     if ( debug & DEBUG_AUTHEN_FLAG ) 
     		report(LOG_DEBUG, "LDAP authentication Success (%d=%s)", err, ldap_err2string(err));
     ldap_unbind_s(ld); 

     /* Added by Olivier BEDOUET 2009/11/09 */
     s_free(dn);
     return 0;
  }
}
#endif /* LDAP */
