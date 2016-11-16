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

Changelog:
 - 2010/29/1: added remoteacl
*/

/* Keywords of the configuration language */

#include "tac_plus.h"

static void *wordtable[HASH_TAB_SIZE];	/* Table of keyword declarations */

struct keyword {
    char *word;
    void *hash;
    u_char value;
};

typedef struct keyword KEYWORD;

static void
declare(name, value)
    char *name;
    int value;
{
    KEYWORD *n;
    KEYWORD *k = (KEYWORD *)tac_malloc(sizeof(KEYWORD));

    k->word = tac_strdup(name);
    k->value = value;

    n = hash_add_entry(wordtable, (void *) k);

    if (n) {
	report(LOG_ERR, "Attempt to multiply define keyword %s",
	       name);
	s_free(k);
	tac_exit(1);
    }
}

/* Declare keywords of the "configuration language". */

void 
parser_init()
{
    bzero(wordtable, sizeof(wordtable));

    declare("access", S_access);
    declare("accounting", S_accounting);
#ifdef ACLS
    declare("acl", S_acl);
    declare("enableacl", S_enableacl);
    declare("remoteacl", S_remoteacl);
#endif
    declare("after", S_after);
    declare("arap", S_arap);
    declare("attribute", S_attr);
    declare("authentication", S_authentication);
    declare("authorization", S_authorization);
    declare("before", S_before);
    declare("chap", S_chap);
#ifdef MSCHAP
    declare("ms-chap", S_mschap);
#endif /* MSCHAP */
    declare("cleartext", S_cleartext);
#ifdef USE_PAM
    declare("pam", S_pam);
#endif /*USE_PAM */
    declare("nopassword", S_nopasswd);
    declare("cmd", S_cmd);
    declare("default", S_default);
    declare("deny", S_deny);
    declare("des", S_des);
    declare("exec", S_exec);
    declare("expires", S_expires);
    declare("file", S_file);
    declare("group", S_group);
    declare("global", S_global);
    declare("host", S_host);
    declare("type", S_type);
    declare("ip", S_ip);
    declare("ipx", S_ipx);
    declare("key", S_key);
    declare("lcp", S_lcp);
#ifdef MAXSESS
    declare("maxsess", S_maxsess);
#endif
#ifdef DB
    declare("db", S_db);
    declare("db_accounting",S_db_accounting);
#endif
#ifdef USE_LDAP
    declare ("ldap", S_ldap);
#endif
    declare("member", S_member);
    declare("message", S_message);
    declare("name", S_name);
    declare("optional", S_optional);
    declare("login", S_login);
    declare("permit", S_permit);
    declare("pap", S_pap);
    declare("opap", S_opap);
    declare("ppp", S_ppp);
    declare("protocol", S_protocol);
    declare("skey", S_skey);
    declare("slip", S_slip);
    declare("service", S_svc);
    declare("user", S_user);
    declare("time", S_time);
    declare("prompt",S_prompt);
    declare("enable",S_enable);
}

/* Return a keyword code if a keyword is recognized. 0 otherwise */
int
keycode(keyword)
char *keyword;
{
    KEYWORD *k = hash_lookup(wordtable, keyword);

    if (k)
	return (k->value);
    return (S_unknown);
}

char *
codestring(type)
int type;
{
    switch (type) {
    default:
	return ("<unknown symbol>");
    case S_eof:
	return ("end-of-file");
    case S_unknown:
	return ("unknown");
    case S_separator:
	return ("=");
    case S_string:
	return ("<string>");
    case S_openbra:
	return ("{");
    case S_closebra:
	return ("}");
#ifdef ACLS
    case S_acl:
        return("acl");
    case S_enableacl:
        return("enableacl");
    case S_remoteacl:
        return("remoteacl");
#endif
    case S_key:
	return ("key");
    case S_user:
	return ("user");
    case S_group:
	return ("group");
    case S_host:
	return ("host");
    case S_type:
	return ("type");
    case S_file:
	return ("file");
    case S_skey:
	return ("skey");
    case S_name:
	return ("name");
    case S_login:
	return ("login");
    case S_member:
	return ("member");
#ifdef MAXSESS
    case S_maxsess:
	return ("maxsess");
#endif
#ifdef DB
    case S_db:
        return ("db");
    case S_db_accounting:
	return ("db_accounting");
#endif
   case S_expires:
	return ("expires");
    case S_after:
	return ("after");
    case S_before:
	return ("before");
    case S_message:
	return ("message");
    case S_arap:
	return ("arap");
    case S_global:
	return ("global");
    case S_chap:
	return ("chap");
#ifdef MSCHAP
    case S_mschap:
	return ("ms-chap");
#endif /* MSCHAP */
    case S_pap:
	return ("pap");
    case S_opap:
	return ("opap");
    case S_cleartext:
	return ("cleartext");
#ifdef USE_PAM
    case S_pam:
	return ("pam");
#endif /*USE_PAM */	
    case S_nopasswd:
	return("nopassword");
    case S_des:
	return("des");
    case S_svc:
	return ("service");
    case S_default:
	return ("default");
    case S_access:
	return ("access");
    case S_deny:
	return ("deny");
    case S_permit:
	return ("permit");
    case S_exec:
	return ("exec");
    case S_protocol:
	return ("protocol");
    case S_optional:
	return ("optional");
    case S_ip:
	return ("ip");
    case S_ipx:
	return ("ipx");
    case S_slip:
	return ("slip");
    case S_ppp:
	return ("ppp");
    case S_authentication:
	return ("authentication");
    case S_authorization:
	return ("authorization");
    case S_cmd:
	return ("cmd");
    case S_attr:
	return ("attribute");
    case S_svc_dflt:
	return ("svc_dflt");
    case S_accounting:
	return ("accounting");
    case S_lcp:
	return("lcp");
    case S_time:
	return("time");
    case S_prompt:
        return("prompt");
    case S_enable:
        return("enable");
    }
}
