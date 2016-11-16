#ifdef USE_PAM

/* tac_pam.auth.c
 * A simple pam authentication  routine written by 
 * Max Liccardo <ravel@tiscalinet.it>
 * PAM_RUSER=username/rem_addr.
 */

 /*
    This program was contributed by Shane Watts
    [modifications by AGM]

    You need to add the following (or equivalent) to the /etc/pam.conf file.
    # check authorization
    check_user   auth       required     /usr/lib/security/pam_unix_auth.so
    check_user   account    required     /usr/lib/security/pam_unix_acct.so
   */
/*
 * Modified by Olivier BEDOUET
 *
 * ChangeLog:
 *  - 2009/12/7: replaced calloc() by s_malloc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include "tac_plus.h"

typedef struct
{
	char *UserName;
	char *Passwd;
} UserCred;


static int fconv(int num_msg, const struct pam_message **msg,
		struct pam_response **resp,void *appdata_ptr)
{
	int 		i;
    UserCred	*lUserCred;


	lUserCred  = appdata_ptr;

	if(lUserCred == NULL)
	{
		report(LOG_ERR,"argh....maybe a SunOs 5.6 ???");
		return(PAM_CONV_ERR);
	}


	*resp = (struct pam_response *) calloc(num_msg,sizeof(struct pam_response));	
	
	for(i=0;i<num_msg;i++)
	{
		switch(msg[i]->msg_style)
		{
			case PAM_PROMPT_ECHO_OFF:
                resp[i]->resp = strdup(lUserCred->Passwd);
                break;
			
			case PAM_PROMPT_ECHO_ON:
                resp[i]->resp = strdup(lUserCred->UserName);
                break;		
			
			default:
				 report(LOG_DEBUG,"conv default");
			break;
		}
		resp[i]->resp_retcode = 0;
	}

	return(PAM_SUCCESS);
}




int
tac_pam_auth(char *aszUserName,char *aszPassword,struct authen_data *data,char *aszService)
{
   	pam_handle_t 	*pamh=NULL;
   	int 			retval;
	char 			*lpszRemoteUser;   				/* Username/NAC address */
    struct pam_conv s_conv;
	UserCred		s_UserCred;


	s_UserCred.UserName = aszUserName;
    s_UserCred.Passwd 	= aszPassword;

	s_conv.conv = fconv;
    s_conv.appdata_ptr = (void *) &s_UserCred;


	/*if((lpszRemoteUser = calloc(strlen(aszUserName)+strlen(data->NAS_id->NAC_address)+2,sizeof(char))) == NULL)*/
	if((lpszRemoteUser = s_malloc((strlen(aszUserName)+strlen(data->NAS_id->NAC_address)+2)*sizeof(char))) == NULL)
	{
        report(LOG_ERR,"cannot malloc");
		return(1);
	}

   	retval = pam_start(aszService,aszUserName , &s_conv, &pamh);

 	if (retval != PAM_SUCCESS)
   	{
	    report(LOG_ERR, "cannot start pam-authentication");	
		pamh = NULL;
		return(1);
    }

    sprintf(lpszRemoteUser,"%s:%s",aszUserName,data->NAS_id->NAC_address);

    pam_set_item(pamh,PAM_RUSER,lpszRemoteUser);
    pam_set_item(pamh,PAM_RHOST,data->NAS_id->NAS_name);
    pam_set_item(pamh,PAM_TTY,data->NAS_id->NAS_port);

	s_free(lpszRemoteUser);

    retval = pam_authenticate(pamh,0); 				/* is user really user? */

    if(retval != PAM_SUCCESS)
     	report(LOG_ERR, "%s",pam_strerror(pamh,retval));
    
    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
		pamh = NULL;
		return(1);
	}

    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */
}


/* PAM authorization rotine written by
 * Devrim SERAL <devrim@tef.gazi.edu.tr>
*/

int
tac_pam_authorization (char *aszUserName,struct author_data *data,char *aszService)
{
   	pam_handle_t 	*pamh=NULL;
   	int 			retval;
	char 			*lpszRemoteUser;   				/* Username/NAC address */
	struct pam_conv s_conv;
	UserCred		s_UserCred;


	s_UserCred.UserName = aszUserName;

	s_conv.conv = fconv;
        s_conv.appdata_ptr = (void *) &s_UserCred;

	if (aszService== NULL) 
	{
	report(LOG_ERR,"Service Name doesn't available So authorize him");
                return(0);
        }
	

	/*if((lpszRemoteUser = calloc(strlen(aszUserName)+strlen(data->id->NAC_address)+2,sizeof(char))) == NULL)*/
	if((lpszRemoteUser = s_malloc((strlen(aszUserName)+strlen(data->id->NAC_address)+2)*sizeof(char))) == NULL)
	{
        report(LOG_ERR,"cannot malloc");
		return(1);
	}

   	retval = pam_start(aszService,aszUserName , &s_conv, &pamh);

 	if (retval != PAM_SUCCESS)
   	{
	    report(LOG_ERR, "cannot start pam-authentication");	
		pamh = NULL;
		return(1);
    }

    sprintf(lpszRemoteUser,"%s:%s",aszUserName,data->id->NAC_address);

    pam_set_item(pamh,PAM_RUSER,lpszRemoteUser);
    pam_set_item(pamh,PAM_RHOST,data->id->NAS_name);
    pam_set_item(pamh,PAM_TTY,data->id->NAS_port);

	s_free(lpszRemoteUser);

    retval = pam_acct_mgmt(pamh, 0); /* Is user permit to gain access system */
    
    if(retval != PAM_SUCCESS)
        report(LOG_ERR, "Pam Account Managment:%s",pam_strerror(pamh,retval));
    else 
	if (debug & DEBUG_AUTHOR_FLAG)
        report(LOG_DEBUG, "PAM authorization allow user");    
    
   if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
		pamh = NULL;
		return(1);
	}

    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */
}


#endif /* USE_PAM */




