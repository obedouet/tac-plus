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

Modified by Olivier BEDOUET
ChangeLog:
 - 2009/04/12: integrated change from version F4.0.4.14 :
"Log login failures with the username, NAS address and NAS tty -
          requested by Andi Bauer"
 - 2010/1/29: added remoteacl support with verify_remote_host() and
 call from tac_login() (with some checks inside)
 - 2011/4/12: modified login failure message to display NAC_address
*/

#include "tac_plus.h"
#include "expire.h"
#include "md5.h"

#ifdef MSCHAP
#include "md4.h"
#include "mschap.h"

#ifdef MSCHAP_DES
#include "arap_des.h"
#endif
#endif /* MSCHAP */

#ifdef ARAP_DES
#include "arap_des.h"
#endif

extern void *usertable[HASH_TAB_SIZE];        /* Table of user declarations */
extern void *grouptable[HASH_TAB_SIZE];/* Table of group declarations */

/* internal state variables */
#define STATE_AUTHEN_START   0	/* no requests issued */
#define STATE_AUTHEN_GETUSER 1	/* username has been requested */
#define STATE_AUTHEN_GETPASS 2	/* password has been requested */

struct private_data {
    char password[MAX_PASSWD_LEN + 1];
    int state;
};

static void chap_verify();
#ifdef MSCHAP
static void mschap_verify();
#endif /* MSCHAP */
static void arap_verify();
static void pap_verify();
static void tac_login();

/*
 * Default tacacs login authentication function. Wants a username
 * and a password, and tries to verify them.
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
default_fn(data)
struct authen_data *data;
{
    struct private_data *p;
    char *name = data->NAS_id->username;

    p = (struct private_data *) data->method_data;

    /* An abort has been received. Clean up and return */
    if (data->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
	if (data->method_data)
	    s_free(data->method_data);
	data->method_data = NULL;
	return (1);
    }
    /* Initialise method_data if first time through */
    if (!p) {
	p = (struct private_data *) tac_malloc(sizeof(struct private_data));
	bzero(p, sizeof(struct private_data));
	data->method_data = p;
	p->state = STATE_AUTHEN_START;
    }
    if (STREQ(name, DEFAULT_USERNAME)) {
	/* Never authenticate this user. It's for authorization only */
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	if (debug) {
	    report(LOG_DEBUG,
		   "authentication query for '%s' %s from %s rejected",
		   name && name[0] ? name : "unknown",
		   session.port, session.peer);
	}
	return (0);
    }
    if (data->action != TAC_PLUS_AUTHEN_LOGIN) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
    } else {
	switch (data->type) {
	case TAC_PLUS_AUTHEN_TYPE_CHAP:
	    /* set status inside chap_verify */
	    chap_verify(data);

	    if (debug) {
		report(LOG_DEBUG, "chap-login query for '%s' %s from %s %s",
		       name && name[0] ? name : "unknown",
		       session.port, session.peer,
		       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		       "accepted" : "rejected");
	    }
	    break;

#ifdef MSCHAP
	case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
	    /* set status inside mschap_verify */
	    mschap_verify(data);

	    if (debug) {
		report(LOG_DEBUG, "mschap-login query for '%s' %s from %s %s",
		       name && name[0] ? name : "unknown",
		       session.port, session.peer,
		       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		       "accepted" : "rejected");
	    }
	    break;
#endif /* MSCHAP */

	case TAC_PLUS_AUTHEN_TYPE_ARAP:
	    /* set status inside arap_verify */
	    arap_verify(data);

	    if (debug) {
		report(LOG_DEBUG, "arap query for '%s' %s from %s %s",
		       name && name[0] ? name : "unknown",
		       session.port, session.peer,
		       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		       "accepted" : "rejected");
	    }
	    break;

	case TAC_PLUS_AUTHEN_TYPE_PAP:
	    pap_verify(data);

	    if (debug) {
		report(LOG_INFO, "pap-login query for '%s' %s from %s %s",
		       name && name[0] ? name : "unknown",
		       session.port,
		       session.peer,
		       (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
		       "accepted" : "rejected");
	    }
	    break;

	case TAC_PLUS_AUTHEN_TYPE_ASCII:
	    tac_login(data, p);
	    switch (data->status) {
	    case TAC_PLUS_AUTHEN_STATUS_GETPASS:
	    case TAC_PLUS_AUTHEN_STATUS_GETUSER:
	    case TAC_PLUS_AUTHEN_STATUS_GETDATA:
		/* Authentication still in progress. More data required */
		return (0);

	    default:
		/* Authentication finished */
		if (debug)
		    report(LOG_INFO, "login query for '%s' %s from %s %s",
			   name && name[0] ? name : "unknown",
			   session.port,
			   session.peer,
			   (data->status == TAC_PLUS_AUTHEN_STATUS_PASS) ?
			   "accepted" : "rejected");
	    }
	    break;

	default:
	    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	    break;
	}
    }

    if (data->method_data)
	s_free(data->method_data);
    data->method_data = NULL;

    switch (data->status) {
    case TAC_PLUS_AUTHEN_STATUS_ERROR:
    case TAC_PLUS_AUTHEN_STATUS_FAIL:
	 if (session.peer)
            report(LOG_NOTICE, "login failure: %s %s (%s) %s",
                   name == NULL ? "unknown" : name,
                   session.peer, data->NAS_id->NAC_address, session.port);	/* Replaced session.peerip by NAC_address */
        else
            report(LOG_NOTICE, "login failure: %s %s %s",
                   name == NULL ? "unknown" : name,
                   session.peerip, session.port);
    case TAC_PLUS_AUTHEN_STATUS_PASS:
	return (0);

    default:
	report(LOG_ERR, "%s %s: default_fn set bogus status value %d",
	       session.peer, session.port, data->status);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return (0);
    }
}

/* Do a login requiring a username & password. We already know the
 * username. We may return GETPASS to get a password if we need it.
 * The password will be stored in the private data
 *
 */

static void
tac_login(data, p)
struct authen_data *data;
struct private_data *p;
{
    char *name=NULL, *passwd=NULL;	/* Olivier BEDOUET: vars are default-initialized */
    int pwlen=0;

    if (data != NULL) /* Check added by Olivier BEDOUET */
        name = data->NAS_id->username;

    /*if (!name[0]) { Olivier BEDOUET: dirty check*/
    if (data==NULL || name==NULL || name[0]=='\0') {
	/* something awful has happened. Give up and die */
	report(LOG_ERR, "%s %s: no username for login",
	       session.peer, session.port);
	if (data != NULL) /* Check added by Olivier BEDOUET */
	    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    /* Do we have a password? */
    if (p != NULL) /* Check added by Olivier BEDOUET */
        passwd = p->password;
    else
    {
	report(LOG_ERR, "%s %s: no password for login",
               session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }

    /*if (!passwd[0]) { Olivier BEDOUET: dirty check*/
    if (passwd==NULL || passwd[0]=='\0') {

	/* no password yet. Either we need to ask for one and expect to get
	 * called again when it's supplied, or we already asked for one and
	 * we should have a reply. */

	switch (p->state) {
	case STATE_AUTHEN_GETPASS:
	    /* We already asked for a password. This should be the reply */
	    if (data->client_msg) {
		pwlen = MIN((int) strlen(data->client_msg), MAX_PASSWD_LEN);
	    } else {
		pwlen = 0;
	    }
	    strncpy(passwd, data->client_msg, pwlen);
	    passwd[pwlen] = '\0';
	    break;

	case STATE_AUTHEN_START:
	    /* if we're at the username stage, and the user has
	     * nopasswd defined, then return a PASS
	     */
	    if (cfg_get_user_nopasswd(name, TAC_PLUS_RECURSE)) {
    		if (debug & DEBUG_AUTHEN_FLAG)
		    report(LOG_DEBUG, "tac_login(): pass");
		data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
		return;
	    }
	    /* FALL-THRU */
	default:
    	    if (debug & DEBUG_AUTHEN_FLAG)
	        report(LOG_DEBUG, "tac_login(): asking password");
	    data->flags = TAC_PLUS_AUTHEN_FLAG_NOECHO;
	    data->server_msg = tac_strdup("Password: ");
	    data->status = TAC_PLUS_AUTHEN_STATUS_GETPASS;
	    p->state = STATE_AUTHEN_GETPASS;
	    return;
	}
    }
    /* Now we have a username and password. Try validating */
    if (debug & DEBUG_AUTHEN_FLAG)
	report(LOG_DEBUG, "tac_login(): Try validating password");

    /* Assume the worst */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    verify(name, passwd, data, TAC_PLUS_RECURSE);
#ifdef ACLS
    if (debug & DEBUG_AUTHEN_FLAG)
	report(LOG_DEBUG, "tac_login(): checking acl");
    if (verify_host(name, data, S_acl, TAC_PLUS_RECURSE) != S_permit)
        data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    if (debug & DEBUG_AUTHEN_FLAG)
	report(LOG_DEBUG, "tac_login(): checking remoteacl");
    if (verify_remote_host(name, data, S_remoteacl, TAC_PLUS_RECURSE) != S_permit)
        data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
#endif
    return;
}

/*
 * Process an inbound PAP login. The username & password should be in
 * the START packet.
 */

static void
pap_verify(data)
struct authen_data *data;
{
    char *name, *passwd;

    name = data->NAS_id->username;

    if (!name[0]) {
	/* something awful has happened. Give up and die */
	report(LOG_ERR, "%s %s: no username for inbound PAP login",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    /* get the password */
    passwd = tac_malloc(data->client_dlen + 1);
    bcopy(data->client_data, passwd, data->client_dlen);
    passwd[data->client_dlen] = '\0';

    /* Assume the worst */
    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    verify(name, passwd, data, TAC_PLUS_RECURSE);
    s_free(passwd);
}


/* Verify the challenge and id against the response by looking up the
 * chap secret in the config file. Set data->status appropriately.
 */
static void
chap_verify(data)
struct authen_data *data;
{
    char *name, *secret, *chal, digest[MD5_LEN];
    char *exp_date, *p;
    u_char *mdp;
    char id;
    int chal_len, inlen;
    MD5_CTX mdcontext;

    if (!(char) data->NAS_id->username[0]) {
	report(LOG_ERR, "%s %s: no username for chap_verify",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    name = data->NAS_id->username;

    id = data->client_data[0];

    chal_len = data->client_dlen - 1 - MD5_LEN;
    if (chal_len < 0) {
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    if (debug & DEBUG_AUTHEN_FLAG) {
	report(LOG_DEBUG, "%s %s: chap user=%s, id=%d chal_len=%d",
	       session.peer, session.port, name, (int) id, chal_len);

	/* report_hex(LOG_DEBUG, (u_char *)data->client_data + 1, chal_len); */
    }
    /* Assume failure */
    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;

    /* Get the secret */
    secret = cfg_get_chap_secret(name, TAC_PLUS_RECURSE);

    /* If there is no chap password for this user, see if there is a global
     * password for her that we can use */
    if (!secret) {
	secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
    }
    if (!secret) {
	/* No secret. Fail */
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "%s %s: No chap or global secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }
    p = tac_find_substring("cleartext ", secret);
    if (!p) {
	report(LOG_ERR, "%s %s: %s chap secret %s is not cleartext",
	       session.peer, session.port, name, secret);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    secret = p;

    /* We now have the secret, the id, and the challenge value. Put them all
     * together, and run them through the MD5 digest algorithm. */

    inlen = sizeof(u_char) + strlen(secret) + chal_len;
    mdp = (u_char *) tac_malloc(inlen);
    mdp[0] = id;
    bcopy(secret, &mdp[1], strlen(secret));
    chal = data->client_data + 1;
    bcopy(chal, mdp + strlen(secret) + 1, chal_len);
    MD5Init(&mdcontext);
    MD5Update(&mdcontext, mdp, inlen);
    MD5Final((u_char *) digest, &mdcontext);
    s_free(mdp);

    /* Now compare the received response value with the just calculated
     * digest value.  If they are equal, it's a pass, otherwise it's a
     * failure */

    if (bcmp(digest, data->client_data + 1 + chal_len, MD5_LEN)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

    exp_date = cfg_get_expires(name, TAC_PLUS_RECURSE);
    set_expiration_status(exp_date, data);
}


/*
 * Force the "parity" bit to zero on a password before passing it to
 * des. This is not documented anywhere. (I believe forcing the parity
 * to zero reduces the integrity of the encrypted keys but this is
 * what Apple chose to do).
 */
void 
pw_bitshift(pw)
char *pw;
{
    int i;
    unsigned char pws[8];

    /* key is 0 padded */
    for (i = 0; i < 8; i++)
	pws[i] = 0;

    /* parity bit is always zero (this seem bogus) */
    for (i = 0; i < 8 && pw[i]; i++)
	pws[i] = pw[i] << 1;

    bcopy(pws, pw, 8);
}


static void
arap_verify(data)
struct authen_data *data;
{
    char nas_chal[8], r_chal[8], r_resp[8], secret[8];
    char *name, *cfg_secret, *exp_date, *p;

    if (!(char) data->NAS_id->username[0]) {
	report(LOG_ERR, "%s %s: no username for arap_verify",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    name = data->NAS_id->username;

    bcopy(data->client_data, nas_chal, 8);
    bcopy(data->client_data + 8, r_chal, 8);
    bcopy(data->client_data + 8 + 8, r_resp, 8);

    /* Assume failure */
    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;

    /* Get the secret */
    cfg_secret = cfg_get_arap_secret(name, TAC_PLUS_RECURSE);

    /* If there is no arap password for this user, see if there is a global
     * password for her that we can use */
    if (!cfg_secret) {
	cfg_secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
    }
    if (!cfg_secret) {
	/* No secret. Fail */
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "%s %s: No arap or global secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }
    p = tac_find_substring("cleartext ", cfg_secret);
    if (!p) {
	report(LOG_ERR, "%s %s: %s arap secret %s is not cleartext",
	       session.peer, session.port, name, cfg_secret);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    /* need to allocate 8 bytes for secret, even if it's actually shorter */
    bzero(secret, sizeof(secret));
    strcpy(secret, p);

    pw_bitshift(secret);

#ifdef ARAP_DES
    des_init(0);
    des_setkey(secret);
    des_endes(nas_chal);
    des_done();
#endif				/* ARAP_DES */

    /* Now compare the remote's response value with the just calculated one
     * value.  If they are equal, it's a pass, otherwise it's a failure */

    if (bcmp(nas_chal, r_resp, 8)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

#ifdef ARAP_DES
    /* Now calculate the response to the remote's challenge */
    des_init(0);
    des_setkey(secret);
    des_endes(r_chal);
    des_done();
#endif				/* ARAP_DES */

    data->server_data = tac_malloc(8);
    data->server_dlen = 8;
    bcopy(r_chal, data->server_data, 8);

    exp_date = cfg_get_expires(name, TAC_PLUS_RECURSE);
    set_expiration_status(exp_date, data);
}


#ifdef MSCHAP

/* Following code is added for ms-chap */
static void
mschap_desencrypt(clear, str, cypher)
char *clear;
unsigned char *str;
unsigned char *cypher;
{
    unsigned char key[8];

    /* des_state_type *des_state = NULL; */

    memset(key, 0, 8);

    /* Copy the key inserting parity bits */

#ifdef old
    /* This method makes it obvious what we are doing */

#define getbit(bit,array) ((array[bit/8] & (1 <<  (7-(bit%8)))) !=0)
#define setbit(bit,array) (array[bit/8] |= (1 <<  (7-(bit%8))))

    {
	int i, j;

	j = 0;
	for (i = 0; i < 56; i++) {
	    if (i && (i % 7 == 0)) {
		j++;
	    }
	    if (getbit(i, str))
		setbit(j, key);
	    j++;
	}
    }
#else
    /* this is a little more cryptic, but faster basicly we are insering a
     * bit into the stream after every 7 bits */

    key[0] = ((str[0] & 0xfe));
    key[1] = ((str[0] & 0x01) << 7) | ((str[1] & 0x0fc) >> 1);
    key[2] = ((str[1] & 0x03) << 6) | ((str[2] & 0x0f8) >> 2);
    key[3] = ((str[2] & 0x07) << 5) | ((str[3] & 0x0f0) >> 3);
    key[4] = ((str[3] & 0x0f) << 4) | ((str[4] & 0x0e0) >> 4);
    key[5] = ((str[4] & 0x1f) << 3) | ((str[5] & 0x0c0) >> 5);
    key[6] = ((str[5] & 0x3f) << 2) | ((str[6] & 0x080) >> 6);
    key[7] = ((str[6] & 0x7f) << 1);

#endif

    /* copy clear to cypher, cause our des encrypts in place */
    memcpy(cypher, clear, 8);
/*
    des_init(0,&des_state);
    des_setkey(des_state,key);
    des_endes(des_state,cypher);
    des_done(des_state);
*/
#ifdef MSCHAP_DES
    des_init(0);
    des_setkey(key);
    des_endes(cypher);
    des_done();
#endif				/* MSCHAP_DES */
}


static void
mschap_deshash(clear, cypher)
char *clear;
char *cypher;
{
    mschap_desencrypt(MSCHAP_KEY, clear, cypher);
}


static void
mschap_lmpasswordhash(password, passwordhash)
char *password;
char *passwordhash;
{
    unsigned char upassword[15];
    int i = 0;

    memset(upassword, 0, 15);
    while (password[i]) {
	upassword[i] = toupper(password[i]);
	i++;
    };

    mschap_deshash(&upassword[0], &passwordhash[0]);
    mschap_deshash(&upassword[7], &passwordhash[8]);
}


static void
mschap_challengeresponse(challenge, passwordhash, response)
char *challenge;
char *passwordhash;
char *response;
{
    char zpasswordhash[21];

    memset(zpasswordhash, 0, 21);
    memcpy(zpasswordhash, passwordhash, 16);

    mschap_desencrypt(challenge, &zpasswordhash[0], &response[0]);
    mschap_desencrypt(challenge, &zpasswordhash[7], &response[8]);
    mschap_desencrypt(challenge, &zpasswordhash[14], &response[16]);
}


void
mschap_lmchallengeresponse(challenge, password, response)
char *challenge;
char *password;
char *response;
{
    char passwordhash[16];

    mschap_lmpasswordhash(password, passwordhash);
    mschap_challengeresponse(challenge, passwordhash, response);
}


static int
mschap_unicode_len(password)
char *password;
{
    int i;

    i = 0;
    while ((password[i] || password[i + 1]) && (i < 512)) {
	i += 2;
    }

    return i;
}


static void
mschap_ntpasswordhash(password, passwordhash)
char *password;
char *passwordhash;
{
    MD4_CTX context;
    int i;
    char *cp;
    unsigned char unicode_password[512];

    memset(unicode_password, 0, 512);

    i = 0;
    memset(unicode_password, 0, 512);
    cp = password;
    while (*cp) {
	unicode_password[i++] = *cp++;
	unicode_password[i++] = '\0';
    }

    MD4Init(&context);
    MD4Update(&context, unicode_password,
	      mschap_unicode_len(unicode_password));
    MD4Final(passwordhash, &context);
}


void
mschap_ntchallengeresponse(challenge,
			   password,
			   response)
char *challenge;
char *password;
char *response;
{
    char passwordhash[16];

    mschap_ntpasswordhash(password, passwordhash);
    mschap_challengeresponse(challenge, passwordhash, response);
}


/* Verify the challenge and id against the response by looking up the
 * ms-chap secret in the config file. Set data->status appropriately.
 */
static void
mschap_verify(data)
struct authen_data *data;
{
    char *name, *secret, *chal, *resp;
    char *exp_date, *p;
    char id;
    int chal_len;
    char lmresponse[24];
    char ntresponse[24];
    int bcmp_status;

    if (!(char) data->NAS_id->username[0]) {
	report(LOG_ERR, "%s %s: no username for mschap_verify",
	       session.peer, session.port);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    name = data->NAS_id->username;

    id = data->client_data[0];

    chal_len = data->client_dlen - 1 - MSCHAP_DIGEST_LEN;
    if (data->client_dlen <= (MSCHAP_DIGEST_LEN + 2)) {
	/* Invalid packet or NULL challenge */
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    if (debug & DEBUG_AUTHEN_FLAG) {
	report(LOG_DEBUG, "%s %s: ms-chap user=%s, id=%d chal_len=%d",
	       session.peer, session.port, name, (int) id, chal_len);

	/* report_hex(LOG_DEBUG, (u_char *)data->client_data + 1, chal_len); */
    }
    /* Assume failure */
    data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;

    /* Get the secret */
    secret = cfg_get_mschap_secret(name, TAC_PLUS_RECURSE);

    /* If there is no ms-chap password for this user, see if there is a
     * global password for her that we can use */
    if (!secret) {
	secret = cfg_get_global_secret(name, TAC_PLUS_RECURSE);
    }
    if (!secret) {
	/* No secret. Fail */
	if (debug & DEBUG_AUTHEN_FLAG) {
	    report(LOG_DEBUG, "%s %s: No ms-chap or global secret for %s",
		   session.peer, session.port, name);
	}
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return;
    }
    p = tac_find_substring("cleartext ", secret);
    if (!p) {
	report(LOG_ERR, "%s %s: %s ms-chap secret %s is not cleartext",
	       session.peer, session.port, name, secret);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	return;
    }
    secret = p;

    /* We now have the secret, the id, and the challenge value. Put them all
     * together, and run them through the MD4 digest algorithm. */
    chal = data->client_data + 1;
    resp = data->client_data + 1 + chal_len;

    mschap_lmchallengeresponse(chal, secret, lmresponse);
    mschap_ntchallengeresponse(chal, secret, ntresponse);

    /* Now compare the received response value with the just calculated
     * digest value.  If they are equal, it's a pass, otherwise it's a
     * failure */
    if (resp[48])
	bcmp_status = bcmp(ntresponse, &resp[24], 24);
    else
	bcmp_status = bcmp(lmresponse, &resp[0], 24);

    if (bcmp_status) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

    exp_date = cfg_get_expires(name, TAC_PLUS_RECURSE);
    set_expiration_status(exp_date, data);
}

#endif /* MSCHAP */

#ifdef ACLS
/*
 * Verify that the NAS's peerip matches the host acl filter.
 * Return S_deny if session.peerip is invalid, else S_permit
 */
int
verify_host(char *name, struct authen_data *data, int type, int recurse)
{
    char *val;
    USER *user, *group;

    /* lookup host acl for user */
    if (!cfg_user_exists(name) && cfg_user_exists(DEFAULT_USERNAME)) {
        if (debug & DEBUG_AUTHEN_FLAG) {
            report(LOG_DEBUG, "Authenticating ACLs for user '%s' instead of "
                   "'%s'", DEFAULT_USERNAME, name);
        }
        val = cfg_get_pvalue(DEFAULT_USERNAME, 1, type, recurse);
    } else
        /*val = cfg_get_pvalue(name, 1, type, recurse);*/
        val = cfg_get_pvalue(name, 1, type, 0);

    /* no host acl for user */
    if (val == NULL)
    {
	if (debug & DEBUG_AUTHEN_FLAG)
	    report(LOG_DEBUG, "No host ACL for user %s, trying group...", name);
        /* Try group */
        /* find the user/group entry */
        user = (USER *) hash_lookup(usertable, name);
        if (user && user->member)
        {
            group = (USER *) hash_lookup(grouptable, user->member);
            while (group)
	    {
	        if (debug & DEBUG_AUTHEN_FLAG)
		    report(LOG_DEBUG, "Looking for ACL in group %s", group->name);
                val = cfg_get_pvalue(group->name, 0, type, 0);
                if (val)
		{
                    if (cfg_acl_check(val, data->NAS_id->NAS_ip)==S_deny)
			return (S_deny); /* Stop if a deny statement is found */
		}
		else
	            if (debug & DEBUG_AUTHEN_FLAG)
		       report(LOG_DEBUG, "No ACL for group %s", group->name);

		/* Try a next group entry */
		if (group->member)
		    group = (USER *) hash_lookup(grouptable, group->member);
		else
		    group = NULL;
	    }
        }
	else
	{
	    if (debug & DEBUG_AUTHEN_FLAG)
	        report(LOG_DEBUG, "... no group find for user %s", name);
	}
        return(S_permit);
    }


    return(cfg_acl_check(val, data->NAS_id->NAS_ip));
}

/*
 * Verify that the NAS's remoteip matches the host acl filter.
 * Return S_deny if session.peerip is invalid, else S_permit
 */
int
verify_remote_host(char *name, struct authen_data *data, int type, int recurse)
{
    char *val;
    USER *user, *group;

    /* lookup host acl for user */
    if (!cfg_user_exists(name) && cfg_user_exists(DEFAULT_USERNAME)) {
        if (debug & DEBUG_AUTHEN_FLAG) {
            report(LOG_DEBUG, "Authenticating ACLs for user '%s' instead of "
                   "'%s'", DEFAULT_USERNAME, name);
        }
        val = cfg_get_pvalue(DEFAULT_USERNAME, 1, type, recurse);
    } else
        /*val = cfg_get_pvalue(name, 1, type, recurse);*/
        val = cfg_get_pvalue(name, 1, type, 0);

    /* no host acl for user */
    if (val == NULL)
    {
	if (debug & DEBUG_AUTHEN_FLAG)
	    report(LOG_DEBUG, "No host ACL for user %s, trying group...", name);
        /* Try group */
        /* find the user/group entry */
        user = (USER *) hash_lookup(usertable, name);
        if (user && user->member)
        {
            group = (USER *) hash_lookup(grouptable, user->member);
            while (group)
	    {
	        if (debug & DEBUG_AUTHEN_FLAG)
		    report(LOG_DEBUG, "Looking for ACL in group %s", group->name);
                val = cfg_get_pvalue(group->name, 0, type, 0);
                if (val)
		{
	            if (debug & DEBUG_AUTHEN_FLAG)
		        report(LOG_DEBUG, "Checking ACL %s against %s", val, data->NAS_id->NAC_address);
                    if (cfg_acl_check(val, data->NAS_id->NAC_address)==S_deny)
			return (S_deny); /* Stop if a deny statement is found */
		}
		else
	            if (debug & DEBUG_AUTHEN_FLAG)
		       report(LOG_DEBUG, "No ACL for group %s", group->name);

		/* Try a next group entry */
		if (group->member)
		    group = (USER *) hash_lookup(grouptable, group->member);
		else
		    group = NULL;
	    }
        }
	else
	{
	    if (debug & DEBUG_AUTHEN_FLAG)
	        report(LOG_DEBUG, "... no group find for user %s", name);
	}
        return(S_permit);
    }
    else
        return(cfg_acl_check(val, data->NAS_id->NAC_address));
}

#endif

