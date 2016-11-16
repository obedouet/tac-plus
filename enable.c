/* 
   Copyright (c) 1995-1998 by Cisco systems, Inc.

   Permission to use, copy, modify, and distribute this software for
   any purpose and without fee is hereby granted, provided that this
   copyright and permission notice appear on all copies of the
   software and supporting documentation, the name of Cisco Systems,
   Inc. not be used in advertising or publicity pertaining to
   distribution of the program without specific prior permission, and
   notice be given in supporting documentation that modification,
   copying and distribution is by permission of Cisco Systems, Inc.

   Cisco Systems, Inc. makes no representations about the suitability
   of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
   IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
   WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
   FITNESS FOR A PARTICULAR PURPOSE.

Modified by : BEDOUET Olivier / Olivier BEDOUET
ChangeLog:
 - added a function enable_user_verify() 
 - removed compatibility support for $enable$ account
 - added LDAP support
---------------------------------------------------------
Changes by Olivier BEDOUET 2010/02/22:
 - BUG: debug report() do not work !!!
 - Added support for "file /etc/passwd" authentication
 - Added more debug report()

*/

#include "tac_plus.h"
#include "expire.h"

/* internal state variables */
#define STATE_AUTHEN_START   0	/* no requests issued */
#define STATE_AUTHEN_GETUSER 1	/* username has been requested */
#define STATE_AUTHEN_GETPASS 2	/* password has been requested */

struct private_data {
    char password[MAX_PASSWD_LEN + 1];
    int state;
};

int
enable_host_verify(passwd,data)
char *passwd;
struct authen_data *data;
{
char *enable,*p;
if(enable=(char *)cfg_get_host_enable(data->NAS_id->NAS_name)) {
   p = tac_find_substring("cleartext ", enable);
   if (p) {	
        if (strcmp(passwd, p)) {
            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Enable cleartext password is incorrect");
            data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
        } else {
            data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Enable cleartext password is correct");
	    return(1);
        }
   }
   p = tac_find_substring("des ", enable);
   if (p) {	
        if (!des_verify(passwd, p)) {
            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Enable des password is incorrect");
            data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
        } else {
            data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Enable des password is correct");
	    return(1);
        }
    }
} 
return(0);

}

/*
 * This func is a copy of enable_host_verify() and look for the password
 * of the user
 * Added by Olivier BEDOUET
 */
int
enable_user_verify(passwd,data)
char *passwd;
struct authen_data *data;
{
char *enable,*p;
if(enable=(char *)cfg_get_login_secret(data->NAS_id->username, 1)) {
   p = tac_find_substring("cleartext ", enable);
   if (p) {	
        if (strcmp(passwd, p)) {
            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Username cleartext password is incorrect");
            data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
        } else {
            data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Username cleartext password is correct");
	    return(1);
        }
   }
   p = tac_find_substring("des ", enable);
   if (p) {	
        if (!des_verify(passwd, p)) {
            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Username des password is incorrect");
            data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
        } else {
            data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Username des password is correct");
	    return(1);
        }
    }

    /* Added by Olivier BEDOUET 2010/02/22 */
    /* Check for file auth for user */
    p = tac_find_substring("file ", enable);
    if (p) {
        if (!etc_passwd_file_verify(data->NAS_id->username, passwd, data))
	{
	    if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Username file password is incorrect");
            data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	}
	else
	{
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

            if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Username file password is correct");
            return(1);
	}
    }
    /* End of Add */

#ifdef USE_LDAP
    /* Added by Olivier BEDOUET 2009/11/10
     * Check LDAP auth for user
     */
    p = tac_find_substring("ldap", enable);
    if (p) {
        if (ldap_verify(data->NAS_id->username, passwd, p)==1) {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Username ldap password is incorrect");
            data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
        } else {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Username ldap password is correct");
            data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	    return 1;
        }
    }
#endif /* USE_LDAP */
} 
return(0);

}


static void
enable(passwd, data)
char *passwd;
struct authen_data *data;
{
    int level = data->NAS_id->priv_lvl;

    /* sanity check */
    if (level < TAC_PLUS_PRIV_LVL_MIN || level > TAC_PLUS_PRIV_LVL_MAX) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	data->server_msg = tac_strdup("Invalid privilege level in packet");
	report(LOG_ERR, "%s level=%d %s", session.peer, level, data->server_msg);
	return;
    }
    /* 0 <= level <= 14: look for $enab<n>$ and verify */
    /* REMOVED BY Olivier BEDOUET
    if (level < TAC_PLUS_PRIV_LVL_MAX) {
	char buf[11];

	sprintf(buf, "$enab%d$", level);
	if (!verify(buf, passwd, data, TAC_PLUS_NORECURSE))
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }
	*/

    /* 2). level=15. Try $enab15$ or $enable$ (for backwards
       compatibility) and verify */
    
    /* But firstly check wether if we have host enable password */
    
    if(enable_host_verify(passwd,data)) {
    	return;
    }

    /* The following permit the use of the user's enable password
     * instead of the NAS
     * Added by Olivier BEDOUET
     */
    if(enable_user_verify(passwd,data)) {
    	return;
    }

    /* REMOVED BY Olivier BEDOUET
    if (verify("$enable$", passwd, data, TAC_PLUS_NORECURSE) ||
	verify("$enab15$", passwd, data, TAC_PLUS_NORECURSE)) {
	return;
    }
    */

    /* return fail */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    return;
}


/*
 * Tacacs enable authentication function. Wants an enable
 * password, and tries to verify it.
 *
 * Choose_authen will ensure that we already have a username before this
 * gets called.
 *
 * We will query for a password and keep it in the method_data.
 *
 * Any strings returned via pointers in authen_data must come from the
 * heap. They will get freed by the caller.
 *
 * Return 0 if data->status is valid, otherwise 1
 */

int
enable_fn(data)
struct authen_data *data;
{
    char *passwd;
    struct private_data *p;
    int pwlen;

    p = (struct private_data *) data->method_data;

    /* An abort has been received. Clean up and return */
    if (data->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
	if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "An abort has been received. Clean up and return");
	if (data->method_data)
	    s_free(data->method_data);
	data->method_data = NULL;
	return (1);
    }
    /* Initialise method_data if first time through */
    if (!p) {
	if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Initialise method_data (first time through)");
	p = (struct private_data *) tac_malloc(sizeof(struct private_data));
	bzero(p, sizeof(struct private_data));
	data->method_data = p;
	p->state = STATE_AUTHEN_START;
    }

    /* As we're enabling, we don't need a username, but do we have a
       password? */

    if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Do we have a password ?");
    passwd = p->password;

    if (!passwd[0]) {

	/* No password. Either we need to ask for one and expect to get
	 * called again, or we asked but nothing came back, which is fatal */
	if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "No password");

	switch (p->state) {
	case STATE_AUTHEN_GETPASS:
	    /* We already asked for a password. This should be the
               reply */
	    if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "We already asked for a password. This should be the reply");
	    if (data->client_msg) {
		pwlen = MIN((int)strlen(data->client_msg), MAX_PASSWD_LEN);
	    } else {
		pwlen = 0;
	    }
	    strncpy(passwd, data->client_msg, pwlen);
	    passwd[pwlen] = '\0';
	    break;

	default:
	    /* Request a password */
	    if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Request a password");
	    data->flags = TAC_PLUS_AUTHEN_FLAG_NOECHO;
	    data->server_msg = tac_strdup("Password: ");
	    data->status = TAC_PLUS_AUTHEN_STATUS_GETPASS;
	    p->state = STATE_AUTHEN_GETPASS;
	    return (0);
	}
    }

    /* We have a password. Try validating */
    if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Yes we have.");

    /* Assume the worst */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

#ifdef ACLS
    /* check enableacl */
    if (verify_host(data->NAS_id->username, data, S_enableacl,
                    TAC_PLUS_RECURSE) != S_permit) {
	if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Rejected by enableacl.");
        data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else {
#endif
        switch (data->service) {
        case TAC_PLUS_AUTHEN_SVC_ENABLE:
	    if (debug & DEBUG_PASSWD_FLAG)
                report(LOG_DEBUG, "Calling enable() to check password");
    	    enable(passwd, data);
    	    if (debug) {
	        char *name = data->NAS_id->username;

	        report(LOG_INFO, "enable query for '%s' %s from %s %s",
		   name && name[0] ? name : "unknown",
		   data->NAS_id->NAS_port && data->NAS_id->NAS_port[0] ?
		       data->NAS_id->NAS_port : "unknown",
		   session.peer, 
		   (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		   "accepted" : "rejected");
	    }
	    break;
        default:
	    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	    report(LOG_ERR, "%s: Bogus service value %d from packet", 
	       session.peer, data->service);
	    break;
	}
#ifdef ACLS
    }
#endif

    if (data->method_data)
	s_free(data->method_data);
    data->method_data = NULL;

    switch (data->status) {
    case TAC_PLUS_AUTHEN_STATUS_ERROR:
    case TAC_PLUS_AUTHEN_STATUS_FAIL:
    case TAC_PLUS_AUTHEN_STATUS_PASS:
	return (0);
    default:
	report(LOG_ERR, "%s: authenticate_fn can't set status %d",
	       session.peer, data->status);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return (1);
    }
}
