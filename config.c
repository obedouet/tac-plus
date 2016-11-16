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

Modified by Olivier BEDOUET 2009/11/10

Changelog:
 - added LDAP support for login directive
 - 2009/3/12: starting ACL support for users
 - 2009/4/12: Allow \'s within quoted words in tac_plus.conf - from Jesse Zbikowski (from F4.0.4.16 version)
 - 2009/7/12: All func are prototyped
 - 2010/29/1: added remoteacl support
 - 2011/14/4: 
    o changed struct host to support ACL def (allowing to define a group of host based on an ACL)
    o modified parse_host() to manage the "acl =" option
    o modified get_hvalue() to manage the "acl" option
    o modified cfg_get_hvalue() to add the search of a host decl match through an ACL
 - 2014/02/26: added ldap for pap option
*/

#define CONFIG_C

#include "tac_plus.h"
#include <stdio.h>
#include <errno.h>
#include "regexp.h"

/* SYNTAX ======================================================

   <config>         := <decl>*

   <decl>           := <top_level_decl> | <user_decl>

   <top_level_decl> := <authen_default> |
                       accounting file = <string>
                       default authorization = permit |
                       key = <string>

   <authen_default> := default authentication = file <filename> 
#if defined(DB)
		    | db <string> )
#endif
   
<permission>     := permit | deny

   <filename>       := <string>

   <password>       := <string>

   <user_decl>      := user = <string> {
                        [ default service = [ permit | deny ] ]
                        <user_attr>*
                        <svc>*
                   }

   <password_spec>  := file <filename> | 
		       skey | 
		       cleartext <password> |
		       des <password> |

#ifdef USE_PAM		
		       pam <pam_service> |
#endif 		
#if defined(DB)		
			db <string>
#endif
		       nopassword

   <user_attr>      :=   name     = <string> |
                         login    = <password_spec> |
        	         member   = <string> |
        	         expires  = <string> |
                	 arap     = cleartext <string> |
	                 chap     = cleartext <string> |
#ifdef MSCHAP
	                 ms-chap  = cleartext <string> |
#endif
	                 pap      = cleartext <string> |
	                 pap      = des <string> |
#ifdef USE_PAM	
	                 pap      = pam <pam_service> |
#endif 		
	                 opap     = cleartext <string> |
	                 global   = cleartext <string> |
        	         msg      = <string>
			 before authorization = <string> |
			 after authorization = <string>

   <svc>            := <svc_auth> | <cmd_auth>

   <cmd_auth>       := cmd = <string> {
                        <cmd-match>*
                    }

   <cmd-match>      := <permission> <string>

   <svc_auth>       := service = ( exec | arap | slip | ppp protocol = <string> {
                        [ default attribute = permit ]
                        <attr_value_pair>*
                    }

   <attr_value_pair> := [ optional ] <string> = <string>

 END OF SYNTAX ============================================ */

static char sym_buf[MAX_INPUT_LINE_LEN];	/* parse buffer */
static int sym_pos=0;           		/* current place in sym_buf */
static int sym_ch;				/* current parse character */
static int sym_code;				/* parser output */
static int sym_line = 1;			/* current line number for parsing */
static FILE *cf = NULL;				/* config file pointer */
static int sym_error = 0;			/* a parsing error has occurred */
static int no_user_dflt = 0;			/* default if user doesn't exist */
static char *authen_default = NULL;		/* top level authentication default */
static int authen_default_method = 0; 		/* For method check */
char *nopasswd_str = "nopassword";

/* Added by Olivier BEDOUET 2009/12/3: ACL struct */
#ifdef ACLS
struct filter {
    int isdeny;
    char *string;
    regexp *string_reg;
    struct filter *next;
};
typedef struct filter FILTER;

struct acl {
    char *name;                 /* acl name */
    void *hash;                 /* hash table next pointer */
    int line;                   /* line number defined on */
    NODE *nodes;                /* list of entrys */
};

typedef struct acl ACL;
#endif
/* End */

/* A host definition structure. Currently unused, but when we start
   configuring host-specific information e.g. per-host keys, this is
   where it should be kept.

   The first 2 fields (name and hash) are used by the hash table
   routines to hash this structure into a table.  Do not (re)move them */

struct host {
    char *name;			/* host name */
    void *hash;			/* hash table next pointer */
    int line;			/* line number defined on */
    char *key;			/* host specific key */
    char *type;			/* host type	     */
    char *prompt;               /* host Login prompt string */
    char *enable;               /* host enable password */
/* Added by Olivier BEDOUET 2011/14/4: ACL entry for host def */
#ifdef ACLS
    ACL *acl;		/* ACL to match host address */
#endif
/* End */
};

typedef struct host HOST;

/* Only the first 2 fields (name and hash) are used by the hash table
   routines to hashh structures into a table.
*/

union hash {
    struct user u;
#ifdef ACLS
    struct acl a;
#endif
    struct host h;
};

typedef union hash HASH;

void *grouptable[HASH_TAB_SIZE];	/* Table of group declarations */
void *usertable[HASH_TAB_SIZE];		/* Table of user declarations */
#ifdef ACLS
void *acltable[HASH_TAB_SIZE];  	/* Table of ACL declarations */
#endif
void *hosttable[HASH_TAB_SIZE];		/* Table of host declarations */

/* Proto for local func =================================== */
#ifdef ACLS
void free_aclstruct(ACL *);
int insert_acl_entry(ACL *, int);
int parse_acl(void);
int cfg_acl_check(char *aclname, char *ip);
#endif
static void sym_get();

#ifdef __STDC__
void parse_error(char *fmt,...);
#endif
char *cfg_nodestring(int type);
void free_attrs(NODE *node);
void free_cmd_matches(NODE *node);
void free_svcs(NODE *node);
void free_userstruct(USER *user);
void free_hoststruct(HOST *host);
void cfg_clean_config(void);
int parse_permission(void);
int parse(int symbol);
int parse_opt_svc_default(void);
int parse_opt_attr_default(void);
int parse_user(void);
int parse_host(void);
void rch(void);
int parse_decls(void);
NODE *parse_svcs(void);
int parse_host(void);
int parse_user(void);
NODE *parse_attrs(void);
NODE *parse_cmd_matches(void);
void getsym(void);
void sym_get(void);
char *sym_buf_add(char c);
void rch(void);
VALUE get_value(USER *user, int field);
VALUE get_hvalue(HOST *host, int field);
int circularity_check(void);
VALUE cfg_get_value(char *name, int isuser, int attr, int recurse);
int cfg_get_intvalue(char *name, int isuser, int attr, int recurse);
char *cfg_get_pvalue(char *name, int isuser, int attr, int recurse);
VALUE cfg_get_hvalue(char *name, int attr);
char *cfg_get_phvalue(char *name, int attr);
int cfg_read_config(char *cfile);
int cfg_user_exists(char *username);
char *cfg_get_expires(char *username, int recurse);
char *cfg_get_timestamp(char *username, int recurse);
int cfg_get_user_nopasswd(char *user, int recurse);
char *cfg_get_arap_secret(char *user, int recurse);
char *cfg_get_chap_secret(char *user, int recurse);
#ifdef MSCHAP
char *cfg_get_mschap_secret(char *user, int recurse);
#endif
char *cfg_get_pap_secret(char *user, int recurse);
char *cfg_get_opap_secret(char *user, int recurse);
char *cfg_get_global_secret(char *user, int recurse);
#ifdef USE_PAM
char *cfg_get_pam_service(char *user, int recurse);
#endif
NODE *cfg_get_cmd_node(char *name, char *cmdname, int recurse);
int cfg_no_user_permitted(void);
char *cfg_get_authen_default(void);
int cfg_get_authen_default_method(void);
int cfg_ppp_is_configured(char *username, int recurse);
char *cfg_get_host_key(char *host);
char *cfg_get_host_enable(char *host);
char *cfg_get_host_prompt(char *host);
char *cfg_get_login_secret(char *user, int recurse);
char **cfg_get_svc_attrs(NODE *svcnode, int *denyp);
NODE *cfg_get_svc_node(char *username, int type, char *protocol, char *svcname, int recurse);
int cfg_user_svc_default_is_permit(char *user);
/* END OF PROTO ============================================ */

#ifdef __STDC__
#include <stdarg.h>		/* ANSI C, variable length args */
void parse_error(char *fmt,...)
#else
#include <varargs.h>		/* has 'vararg' definitions */
/* VARARGS2 */
static void
parse_error(fmt, va_alist)
char *fmt;

va_dcl				/* no terminating semi-colon */
#endif
{
    char msg[256];		/* temporary string */
    va_list ap;

#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    vsprintf(msg, fmt, ap);
    va_end(ap);

    report(LOG_ERR, "%s", msg);
    fprintf(stderr, "Error: %s\n", msg);
    tac_exit(1);
}

char *cfg_nodestring(int type)
{
    switch (type) {
    default:
	return ("unknown node type");
    case N_arg:
	return ("N_arg");
    case N_optarg:
	return ("N_optarg");
    case N_svc:
	return ("N_svc");
    case N_svc_exec:
	return ("N_svc_exec");
    case N_svc_slip:
	return ("N_svc_slip");
    case N_svc_ppp:
	return ("N_svc_ppp");
    case N_svc_arap:
	return ("N_svc_arap");
    case N_svc_cmd:
	return ("N_svc_cmd");
    case N_permit:
	return ("N_permit");
    case N_deny:
	return ("N_deny");
    }
}

void
free_attrs(node)
NODE *node;
{
    NODE *next;

    while (node) {
	switch (node->type) {
	case N_optarg:
	case N_arg:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free_cmd_match %s %s",
		       cfg_nodestring(node->type),
		       node->value);
	    break;
	default:
	    report(LOG_ERR, "Illegal node type %s for free_attrs", 
		   cfg_nodestring(node->type));
	    return;
	}

	s_free(node->value);
	next = node->next;
	s_free(node);
	node = next;
    }
}

#ifdef ACLS
void
free_aclstruct(ACL *acl)
{
    NODE *last, *next = acl->nodes;

    last = next;

    if (debug & DEBUG_CLEAN_FLAG)
        report(LOG_DEBUG, "free_aclstruct %s", acl->name);

    while (next) {
        if (debug & DEBUG_CLEAN_FLAG)
            report(LOG_DEBUG, "free_aclstruct %s %s", acl->name, next->value);
        if (next->value)
            s_free(next->value);
        if (next->value1)
            s_free(next->value1);
        next = next->next;
        s_free(last);
        last = next;
    }

    if (acl->name)
        s_free(acl->name);
}
#endif


void
free_cmd_matches(node)
NODE *node;
{
    NODE *next;

    while (node) {
	if (debug & DEBUG_CLEAN_FLAG)
	    report(LOG_DEBUG, "free_cmd_match %s %s",
		   cfg_nodestring(node->type),
		   node->value);

	s_free(node->value);	/* text */
	s_free(node->value1);	/* regexp compiled text */
	next = node->next;
	s_free(node);
	node = next;
    }
}

void
free_svcs(node)
NODE *node;
{
    NODE *next;

    while (node) {

	switch (node->type) {
	case N_svc_cmd:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free %s %s",
		       cfg_nodestring(node->type), node->value);
	    s_free(node->value);	/* cmd name */
	    free_cmd_matches(node->value1);
	    next = node->next;
	    s_free(node);
	    node = next;
	    continue;

	case N_svc:
	case N_svc_ppp:
	    s_free(node->value1);
	    /* FALL-THROUGH */
	case N_svc_exec:
	case N_svc_arap:
	case N_svc_slip:
	    if (debug & DEBUG_CLEAN_FLAG)
		report(LOG_DEBUG, "free %s", cfg_nodestring(node->type));
	    free_attrs(node->value);
	    next = node->next;
	    s_free(node);
	    node = next;
	    continue;

	default:
	    report(LOG_ERR, "Illegal node type %d for free_svcs", node->type);
	    return;
	}
    }
}

void
free_userstruct(user)
USER *user;
{
    if (debug & DEBUG_CLEAN_FLAG)
	report(LOG_DEBUG, "free %s %s",
	       (user->flags & FLAG_ISUSER) ? "user" : "group",
	       user->name);

    if (user->name)
	s_free(user->name);
    if (user->full_name)
	s_free(user->full_name);
    if (user->login)
	s_free(user->login);
    if (user->member)
	s_free(user->member);
#ifdef ACLS
    if (user->acl)
        s_free(user->acl);
    if (user->enableacl)
        s_free(user->enableacl);
    if (user->remoteacl)
        s_free(user->remoteacl);
#endif
    if (user->expires)
	s_free(user->expires);
    if (user->time)
	s_free(user->time);
    if (user->arap)
	s_free(user->arap);
    if (user->chap)
	s_free(user->chap);
#ifdef MSCHAP
    if (user->mschap)
	s_free(user->mschap);
#endif /* MSCHAP */
    if (user->pap)
	s_free(user->pap);
    if (user->opap)
	s_free(user->opap);
    if (user->global)
	s_free(user->global);
    if (user->msg)
	s_free(user->msg);
    if (user->before_author)
	s_free(user->before_author);
    if (user->after_author)
	s_free(user->after_author);
    free_svcs(user->svcs);
}

void
free_hoststruct(host)
HOST *host;
{
    if (debug & DEBUG_CLEAN_FLAG)
	report(LOG_DEBUG, "free %s",
		host->name);
    if (host->name)
	s_free(host->name);
    
    if (host->key)
	s_free(host->key);
    
    if (host->type)
	s_free(host->type);

    if (host->prompt)
        s_free(host->prompt);
    
    if (host->enable)
        s_free(host->enable);
}

/*
 * Exported routines
 */

/* Free all allocated structures preparatory to re-reading the config file */
void cfg_clean_config(void)
{
    int i;
    USER *entry, *next;
    HOST *host_entry,*hn;
#ifdef ACLS
    ACL *aentry, *anext;
#endif

    if (authen_default) {
	s_free(authen_default);
	authen_default = NULL;
    }
   
   if (authen_default_method) {
	authen_default_method = 0;
    }

    if (session.key) {
	s_free(session.key);
	session.key = NULL;
    }

    if (session.acctfile) {
	s_free(session.acctfile);
	session.acctfile = NULL;
    }
    
    if (session.db_acct) {
	s_free(session.db_acct);
	session.db_acct = NULL;
    }

#ifdef ACLS
    /* clean the acltable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
        aentry = (ACL *) acltable[i];
        while (aentry) {
            anext = aentry->hash;
            free_aclstruct(aentry);
            s_free(aentry);
            aentry = anext;
        }
        acltable[i] = NULL;
    }
#endif

    /* clean the hosttable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	host_entry = (HOST *) hosttable[i];
	while (host_entry) {
	    hn = host_entry->hash;
	    free_hoststruct(host_entry);
	    s_free(host_entry);
	    host_entry = hn;
	}
	hosttable[i] = NULL;
    }

    /* the grouptable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	entry = (USER *) grouptable[i];
	while (entry) {
	    next = entry->hash;
	    free_userstruct(entry);
	    s_free(entry);
	    entry = next;
	}
	grouptable[i] = NULL;
    }

    /* the usertable */
    for (i = 0; i < HASH_TAB_SIZE; i++) {
	entry = (USER *) usertable[i];
	while (entry) {
	    next = entry->hash;
	    free_userstruct(entry);
	    s_free(entry);
	    entry = next;
	}
	usertable[i] = NULL;
    }
}

int
parse_permission()
{
    int symbol = sym_code;

    if (sym_code != S_permit && sym_code != S_deny) {
	parse_error("expecting permit or deny but found '%s' on line %d",
		    sym_buf, sym_line);
	return (0);
    }
    sym_get();

    return (symbol);
}

int
parse(symbol)
int symbol;

{
    if (sym_code != symbol) {
	parse_error("expecting '%s' but found '%s' on line %d",
		    (symbol == S_string ? "string" : codestring(symbol)),
		    sym_buf, sym_line);
	return (1);
    }
    sym_get();
    return (0);
}

int
parse_opt_svc_default(void)
{
    if (sym_code != S_default) {
	return (0);
    }

    parse(S_default);
    parse(S_svc);
    parse(S_separator);
    if (sym_code == S_permit) {
	parse(S_permit);
	return (S_permit);
    }
    parse(S_deny);
    return (S_deny);
}

int parse_opt_attr_default(void)
{
    if (sym_code != S_default)
	return (S_deny);

    parse(S_default);
    parse(S_attr);
    parse(S_separator);
    parse(S_permit);
    return (S_permit);
}

#ifdef ACLS
/* insert an acl entry into the named acl node list */
int
insert_acl_entry(ACL *acl, int isdeny)
{
    NODE *next = acl->nodes;
    NODE *entry = (NODE *) tac_malloc(sizeof(NODE));

    memset(entry, 0, sizeof(NODE));

    entry->type = isdeny;
    entry->value = tac_strdup(sym_buf);
    entry->line = sym_line;

    /* compile the regex */
    entry->value1 = (void *) regcomp((char *) entry->value);
    if (!entry->value1) {
        report(LOG_ERR, "in regex %s on line %d", sym_buf, sym_line);
        tac_exit(1);
    }

    if (acl->nodes == NULL) {
        acl->nodes = entry;
        return(0);
    }

    while (next->next != NULL) {
        next = next->next;
    }
    next->next = entry;

    return(0);
}
/* parse the acl = NAME { allow = regex  deny = regex } */
int
parse_acl(void)
{
    ACL *n;
    ACL *acl = (ACL *) tac_malloc(sizeof(ACL));
    int isdeny = S_permit;

    memset(acl, 0, sizeof(ACL));

    sym_get();
    parse(S_separator);
    acl->name = tac_strdup(sym_buf);
    acl->line = sym_line;

    n = hash_add_entry(acltable, (void *) acl);

    if (n) {
        parse_error("multiply defined acl %s on lines %d and %d", acl->name,
                    n->line, sym_line);
        return(1);
    }
    sym_get();
    parse(S_openbra);

    while (1) {
        switch (sym_code) {
        case S_eof:
            return(0);

        case S_deny:
            isdeny = S_deny;
        case S_permit:
            sym_get();
            parse(S_separator);
            insert_acl_entry(acl, isdeny);
            parse(S_string);
            isdeny = S_permit;
            continue;

        case S_closebra:
            parse(S_closebra);
            return(0);
        default:
            parse_error("Unrecognised keyword %s for acl on line %d", sym_buf,
                        sym_line);

            return(0);
        }
    }
}
#endif


/*
   Parse lines in the config file, creating data structures
   Return 1 on error, otherwise 0 */

int
parse_decls()
{
    no_user_dflt = 0; /* default if user doesn't exist */

    sym_code = 0;
    rch();

#ifdef ACLS
    memset(acltable, 0, sizeof(acltable));
#endif
    bzero(grouptable, sizeof(grouptable));
    bzero(usertable, sizeof(usertable));
    bzero(hosttable, sizeof(hosttable)); 

    sym_get();

    /* Top level of parser */
    while (1) {

	switch (sym_code) {
	case S_eof:
	    return (0);

	case S_accounting:
	    sym_get();
	    parse(S_file);
	    parse(S_separator);
	    if (session.acctfile) 
		s_free(session.acctfile);
	    session.acctfile = tac_strdup(sym_buf);
	    sym_get();
	    continue;

#ifdef DB	
	case S_db_accounting:
	    sym_get();
	    parse(S_separator);
	    if (session.db_acct) 
		s_free(session.db_acct);
	    session.db_acct = tac_strdup(sym_buf);
	    sym_get();
	    continue;
#endif

	case S_default:
	    sym_get();
	    switch (sym_code) {
	    default:
		parse_error(
	        "Expecting default authorization/authentication on lines %d",
			    sym_line);
		return (1);

	    case S_authentication:
		if (authen_default) {
		    parse_error(
		    "Multiply defined authentication default on line %d",
				sym_line);
		    return (1);
		}
		parse(S_authentication);
		parse(S_separator);

	        switch(sym_code) {
                
		case S_file:
#ifdef DB
		case S_db:
#endif
#ifdef USE_LDAP
		case S_ldap:
#endif
#ifdef USE_PAM
		case S_pam:
#endif
                authen_default_method = sym_code;
		break;

		default:
                parse_error("expecting default_method keyword after 'default authentication = ' on line %d",sym_line);
		return (1);
                }
                sym_get();

		authen_default = tac_strdup(sym_buf);
		sym_get();
		continue;

	    case S_authorization:
		parse(S_authorization);
		parse(S_separator);
		parse(S_permit);
		no_user_dflt = S_permit;
		report(LOG_INFO, 
		       "default authorization = permit is now deprecated. Please use user = DEFAULT instead");
		continue;
	    }

	case S_key:
	    /* Process a key declaration. */
	    sym_get();
	    parse(S_separator);
	    if (session.key) {
		parse_error("multiply defined key on lines %d and %d",
			    session.keyline, sym_line);
		return (1);
	    }
	    session.key = tac_strdup(sym_buf);
	    session.keyline = sym_line;
	    sym_get();
	    continue;
	
	case S_host:
	    parse_host();
	    continue;
	
	case S_user:
	case S_group:
	    parse_user();
	    continue;

	    /* case S_host: parse_host(); continue; */
#ifdef ACLS
        case S_acl:
            parse_acl();
            continue;
#endif

	default:
	    parse_error("Unrecognised token %s on line %d", sym_buf, sym_line);
	    return (1);
	}
    }
}

/* Assign a value to a field. Issue an error message and return 1 if
   it's already been assigned. This is a macro because I was sick of
   repeating the same code fragment over and over */

#define ASSIGN(field) \
sym_get(); parse(S_separator); if (field) { \
	parse_error("Duplicate value for %s %s and %s on line %d", \
		    codestring(sym_code), field, sym_buf, sym_line); \
        tac_exit(1); \
    } \
    field = tac_strdup(sym_buf);

int
parse_host(void)
{
    HOST *h;
    HOST *host = (HOST *) tac_malloc(sizeof(HOST));
    char buf[MAX_INPUT_LINE_LEN];

    bzero(host, sizeof(HOST));

    sym_get();
    parse(S_separator);
    host->name = tac_strdup(sym_buf);
    host->line = sym_line;
    
    h = hash_add_entry(hosttable, (void *) host);
    
    if (h) {
        parse_error("multiply defined %s on lines %d and %d",
                    host->name, h->line, sym_line);

	/* Added by Olivier BEDOUET */
	s_free(host);
        return (1);
    }

    sym_get();
    parse(S_openbra);
    
    while (1) {
	switch (sym_code) {
        case S_eof:
            return (0);
	case S_key:
	    ASSIGN(host->key);
            sym_get();
            continue;
	
	case S_type:
	    ASSIGN(host->type);
            sym_get();
            continue;
	
	case S_prompt:
            ASSIGN(host->prompt);
            sym_get();
            continue;	

	case S_enable:
            if (host->enable) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			   codestring(sym_code), host->enable,
			   sym_buf, sym_line);
		tac_exit(1);
            }
	    sym_get();
	    parse(S_separator);
	    switch(sym_code) {
	    
	    case S_cleartext:
            case S_des:	
            	sprintf(buf, "%s ", sym_buf); 
	    	sym_get(); 
	    	strcat(buf, sym_buf); 
	    	host->enable = tac_strdup(buf); 
            	break;
	    default:
		parse_error("expecting 'cleartext' or 'des' keyword after 'enable =' on line %d", sym_line); 
	    }
	    sym_get();
	    continue;	

/* Added by Olivier BEDOUET 2011/14/4 */
#ifdef ACLS
	case S_acl:
	    ASSIGN(host->acl);
            sym_get();
	    continue;
#endif
/* End */
	
	case S_closebra:
            parse(S_closebra);
            return (0);

	default:
	    parse_error("Unrecognised keyword %s for host %s on line %d",
                        sym_buf, host->name,sym_line);

            return (0);
        }
    } /* while */
} /* finish parse_host */


int
parse_user()
{
    USER *n;
    int isuser;
    USER *user = (USER *) tac_malloc(sizeof(USER));
    int save_sym;
    char **fieldp;
    char buf[MAX_INPUT_LINE_LEN];

    bzero(user, sizeof(USER));

    isuser = (sym_code == S_user);

    sym_get();
    parse(S_separator);
    user->name = tac_strdup(sym_buf);
    user->line = sym_line;

    if (isuser) {
	user->flags |= FLAG_ISUSER;
	n = hash_add_entry(usertable, (void *) user);
    } else {
	user->flags |= FLAG_ISGROUP;
	n = hash_add_entry(grouptable, (void *) user);
    }

    if (n) {
	parse_error("multiply defined %s %s on lines %d and %d",
		    isuser ? "user" : "group",
		    user->name, n->line, sym_line);

	/* Added by Olivier BEDOUET */
	s_free(user);
	return (1);
    }
    sym_get();
    parse(S_openbra);

    /* Is the default deny for svcs or cmds to be overridden? */
    user->svc_dflt = parse_opt_svc_default();

    while (1) {
	switch (sym_code) {
	case S_eof:
	    return (0);
	
	case S_time:
	   ASSIGN(user->time);
	   sym_get(); 
	   continue;

	case S_before:
	    sym_get();
	    parse(S_authorization);
	    if (user->before_author)
		s_free(user->before_author);
	    user->before_author = tac_strdup(sym_buf);
	    sym_get();
	    continue;

	case S_after:
	    sym_get();
	    parse(S_authorization);
	    if (user->after_author)
		s_free(user->after_author);
	    user->after_author = tac_strdup(sym_buf);
	    sym_get();
	    continue;

	case S_svc:
	case S_cmd:
	    
	    if (user->svcs) {   
		/* 
		 * Already parsed some services/commands. Thanks to Gabor Kiss
		 * who found this bug.
		 */
		NODE *p;
		for (p=user->svcs; p->next; p=p->next) 
		    /* NULL STMT */;
		p->next = parse_svcs();
	    } else {
		user->svcs = parse_svcs();
	    }
	    continue;

	case S_login:
	    if (user->login) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(sym_code), user->login,
			    sym_buf, sym_line);
		tac_exit(1);
	    }
	    sym_get();
	    parse(S_separator);
	    switch(sym_code) {

	    case S_skey:
		user->login = tac_strdup(sym_buf);
		break;

	    case S_nopasswd:
		/* set to dummy string, so that we detect a duplicate
		 * password definition attempt
		 */
		user->login = tac_strdup(nopasswd_str);
		user->nopasswd = 1;
		break;
		
	    case S_file:
	    case S_cleartext:
	    case S_des:
/* Added by Olivier BEDOUET 2009/11/10 */
#ifdef USE_LDAP
	    case S_ldap:
#endif /* USE_LDAP */
#ifdef USE_PAM	
	    case S_pam:	
#endif /* USE_PAM */		
#ifdef DB
	    case S_db:
#endif /* USE DB */
		sprintf(buf, "%s ", sym_buf);
		sym_get();
		strcat(buf, sym_buf);
		user->login = tac_strdup(buf);
		break;
	
	    default:
#ifdef USE_PAM
		parse_error(
 "expecting 'file', 'cleartext', 'pam'.'nopassword', 'skey', or 'des' keyword after 'login =' on line %d",
			    sym_line);
#else	
		parse_error(
 "expecting 'file', 'cleartext', 'nopassword', 'skey', or 'des' keyword after 'login =' on line %d", 
			    sym_line);
#endif /* USE_PAM */			
	    }
	    sym_get();
	    continue;

	case S_pap:
	    if (user->pap) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(sym_code), user->pap,
			    sym_buf, sym_line);
		tac_exit(1);
	    }
	    sym_get();
	    parse(S_separator);
	    switch(sym_code) {

	    case S_cleartext:
	    case S_des:
/* Added by Olivier BEDOUET 2014/02/26 */
#ifdef USE_LDAP
            case S_ldap:
#endif /* USE_LDAP */
#ifdef USE_PAM	
	    case S_pam:
#endif /*USE_PAM */		    	
		sprintf(buf, "%s ", sym_buf);
		sym_get();
		strcat(buf, sym_buf);
		user->pap = tac_strdup(buf);
		break;	

		sprintf(buf, "%s ", sym_buf);
		user->pap = tac_strdup(buf);
		break;

	    default:
#ifdef USE_PAM
      		parse_error(
 "expecting 'cleartext', 'pam', or 'des' keyword after 'pap =' on line %d",
 sym_line);
#else
		parse_error(
 "expecting 'cleartext', or 'des' keyword after 'pap =' on line %d", 
 sym_line);
#endif /*USE_PAM */
	    }
	    sym_get();
	    continue;

#ifdef ACLS
        case S_acl:
            ASSIGN(user->acl);
            sym_get();
            continue;

        case S_enableacl:
            ASSIGN(user->enableacl);
            sym_get();
            continue;

        case S_remoteacl:
            ASSIGN(user->remoteacl);
            sym_get();
            continue;
#endif

	case S_name:
	    ASSIGN(user->full_name);
	    sym_get();
	    continue;

	case S_member:
	    ASSIGN(user->member);
	    sym_get();
	    continue;
	

	case S_expires:
	    ASSIGN(user->expires);
	    sym_get();
	    continue;
	
	case S_message:
	    ASSIGN(user->msg);
	    sym_get();
	    continue;

	case S_arap:
	case S_chap:
#ifdef MSCHAP
	case S_mschap:
#endif /* MSCHAP */
	case S_opap:
	case S_global:
	    save_sym = sym_code;
	    sym_get(); 
	    parse(S_separator); 
	    sprintf(buf, "%s ", sym_buf);
	    parse(S_cleartext);
	    strcat(buf, sym_buf);

	    if (save_sym == S_arap)
		fieldp = &user->arap;
	    if (save_sym == S_chap)
		fieldp = &user->chap;
#ifdef MSCHAP
	    if (save_sym == S_mschap)
		fieldp = &user->mschap;
#endif /* MSCHAP */
	    if (save_sym == S_pap)
		fieldp = &user->pap;
	    if (save_sym == S_opap)
		fieldp = &user->opap;
	    if (save_sym == S_global)
		fieldp = &user->global;

	    if (*fieldp) {
		parse_error("Duplicate value for %s %s and %s on line %d",
			    codestring(save_sym), *fieldp, sym_buf, sym_line);
		tac_exit(1);
	    }
	    *fieldp = tac_strdup(buf);
	    sym_get();
	    continue;

	case S_closebra:
	    parse(S_closebra);
	    return (0);

#ifdef MAXSESS
	case S_maxsess:
	    sym_get(); 
	    parse(S_separator);
	    if (sscanf(sym_buf, "%d", &user->maxsess) != 1) {
		parse_error("expecting integer, found '%s' on line %d",
		    sym_buf, sym_line);
	    }
	    sym_get();
	    continue;
#endif /* MAXSESS */
 
	default:
	    if (STREQ(sym_buf, "password")) {
		fprintf(stderr,
			"\npassword = <string> is obsolete. Use login = des <string>\n");
	    }
	    parse_error("Unrecognised keyword %s for user on line %d",
			sym_buf, sym_line);

	    return (0);
	}
    }
}

NODE *
parse_svcs(void)
{
    NODE *result;

    switch (sym_code) {
    default:
	return (NULL);
    case S_svc:
    case S_cmd:
	break;
    }

    result = (NODE *) tac_malloc(sizeof(NODE));

    bzero(result, sizeof(NODE));
    result->line = sym_line;

    /* cmd declaration */
    if (sym_code == S_cmd) {
	parse(S_cmd);
	parse(S_separator);
	result->value = tac_strdup(sym_buf);

	sym_get();
	parse(S_openbra);

	result->value1 = parse_cmd_matches();
	result->type = N_svc_cmd;

	parse(S_closebra);
	result->next = parse_svcs();
	return (result);
    }

    /* svc declaration */
    parse(S_svc);
    parse(S_separator);
    switch (sym_code) {
    default:
	parse_error("expecting service type but found %s on line %d",
		    sym_buf, sym_line);

	/* Added by Olivier BEDOUET */
	s_free(result);
	return (NULL);

    case S_string:
	result->type = N_svc;
	/* should perhaps check that this is an allowable service name */
	result->value1 = tac_strdup(sym_buf);
	break;
    case S_exec:
	result->type = N_svc_exec;
	break;
    case S_arap:
	result->type = N_svc_arap;
	break;
    case S_slip:
	result->type = N_svc_slip;
	break;
    case S_ppp:
	result->type = N_svc_ppp;
	parse(S_ppp);
	parse(S_protocol);
	parse(S_separator);
	/* Should perhaps check that this is a known PPP protocol name */
	result->value1 = tac_strdup(sym_buf);
	break;
    }
    sym_get();
    parse(S_openbra);
    result->dflt = parse_opt_attr_default();
    result->value = parse_attrs();
    parse(S_closebra);
    result->next = parse_svcs();
    return (result);
}

/*  <cmd-match>	 := <permission> <string> */

NODE *
parse_cmd_matches(void)
{
    NODE *result;

    if (sym_code != S_permit && sym_code != S_deny) {
	return (NULL);
    }
    result = (NODE *) tac_malloc(sizeof(NODE));

    bzero(result, sizeof(NODE));
    result->line = sym_line;

    result->type = (parse_permission() == S_permit) ? N_permit : N_deny;
    result->value = tac_strdup(sym_buf);

    result->value1 = (void *) regcomp(result->value);
    if (!result->value1) {
	report(LOG_ERR, "in regular expression %s on line %d",
	       sym_buf, sym_line);
	s_free(result);
	tac_exit(1);
    }
    sym_get();

    result->next = parse_cmd_matches();

    return (result);
}

NODE *
parse_attrs(void)
{
    NODE *result;
    char buf[MAX_INPUT_LINE_LEN];
    int optional = 0;

    if (sym_code == S_closebra) {
	return (NULL);
    }
    result = (NODE *) tac_malloc(sizeof(NODE));

    bzero(result, sizeof(NODE));
    result->line = sym_line;

    if (sym_code == S_optional) {
	optional++;
	sym_get();
    }
    result->type = optional ? N_optarg : N_arg;

#ifdef ACLS
    /*
     * "acl" is an acceptable AV for service=exec and may as well be permitted
     * for any other service.  I did not know this when I defined "acl" for
     * connection ACLs.  So, hack it to be a string here.  If the parser were
     * half-way decent, acl just wouldnt be a keyword here.
     */
    if (sym_code == S_acl)
        sym_code = S_string;
#endif
    strcpy(buf, sym_buf);
    parse(S_string);
    strcat(buf, sym_buf);
    parse(S_separator);
    strcat(buf, sym_buf);
    parse(S_string);

    result->value = tac_strdup(buf);
    result->next = parse_attrs();
    return (result);
}


void
sym_get(void)
{
    getsym();

    if (debug & DEBUG_PARSE_FLAG) {
	report(LOG_DEBUG, "line=%d sym=%s code=%d buf='%s'",
	       sym_line, codestring(sym_code), sym_code, sym_buf);
    }
}

char *sym_buf_add(c)
char c;
{
    if (sym_pos >= MAX_INPUT_LINE_LEN) {
	sym_buf[MAX_INPUT_LINE_LEN-1] = '\0';
	if (debug & DEBUG_PARSE_FLAG) {
	    report(LOG_DEBUG, "line too long: line=%d sym=%s code=%d buf='%s'",
		   sym_line, codestring(sym_code), sym_code, sym_buf);
	}
	return(NULL);
    }

    sym_buf[sym_pos++] = c;
    return(sym_buf);
}
    
void getsym(void)
{

next:
    switch (sym_ch) {

    case EOF:
	sym_code = S_eof;
	return;

    case '\n':
	sym_line++;
	rch();
	goto next;

    case '\t':
    case ' ':
	while (sym_ch == ' ' || sym_ch == '\t')
	    rch();
	goto next;

    case '=':
	strcpy(sym_buf, "=");
	sym_code = S_separator;
	rch();
	return;

    case '{':
	strcpy(sym_buf, "{");
	sym_code = S_openbra;
	rch();
	return;

    case '}':
	strcpy(sym_buf, "}");
	sym_code = S_closebra;
	rch();
	return;

    case '#':
	while ((sym_ch != '\n') && (sym_ch != EOF))
	    rch();
	goto next;

    case '"':
	rch();
	sym_pos = 0;
	while (1) {

	    if (sym_ch == '"') {
		break;
	    }

	    /* backslash-double-quote is supported inside strings */
	    /* also allow \n */
	    if (sym_ch == '\\') {
		rch();
		switch (sym_ch) {
		case 'n':
		    /* preserve the slash for \n */
		    if (!sym_buf_add('\\')) {
			sym_code = S_unknown;
			rch();
			return;
		    }
		    
		    /* fall through */
		case '"':
                case '\\':
		    if (!sym_buf_add(sym_ch)) {
			sym_code = S_unknown;
			rch();
			return;
		    }
		    rch();
		    continue;
		default:
		    sym_code = S_unknown;
		    rch();
		    return;
		}
	    }
	    if (!sym_buf_add(sym_ch)) {
		sym_code = S_unknown;
		rch();
		return;
	    }
	    rch();
	}
	rch();

	if (!sym_buf_add('\0')) {
	    sym_code = S_unknown;
	    rch();
	    return;
	}
	sym_code = S_string;
	return;

    default:
	sym_pos = 0;
	while (sym_ch != '\t' && sym_ch != ' ' && sym_ch != '='
	       && sym_ch != '\n') {

	    if (!sym_buf_add(sym_ch)) {
		sym_code = S_unknown;
		rch();
		return;
	    }
	    rch();
	}

	if (!sym_buf_add('\0')) {
	    sym_code = S_unknown;
	    rch();
	    return;
	}
	sym_code = keycode(sym_buf);
	if (sym_code == S_unknown)
	    sym_code = S_string;
	return;
    }
}

void rch(void)
{
    if (sym_error) {
	sym_ch = EOF;
	return;
    }
    sym_ch = getc(cf);

    if (parse_only && sym_ch != EOF)
	fprintf(stderr, "%c", sym_ch);
}


/* For a user or group, find the value of a field. Does not recurse. */
VALUE get_value(user, field)
USER *user;
int field;
{
    VALUE v;

    v.intval = 0;

    if (!user) {
	parse_error("get_value: illegal user");
	return (v);
    }
    switch (field) {

    case S_name:
	v.pval = user->name;
	break;

    case S_login:
	v.pval = user->login;
	break;

    case S_global:
	v.pval = user->global;
	break;

    case S_member:
	v.pval = user->member;
	break;

    case S_expires:
	v.pval = user->expires;
	break;

    case S_arap:
	v.pval = user->arap;
	break;

    case S_chap:
	v.pval = user->chap;
	break;

#ifdef MSCHAP
    case S_mschap:
	v.pval = user->mschap;
	break;
#endif /* MSCHAP */

/* Added by Olivier BEDOUET */
#ifdef ACLS
    case S_acl:
        v.pval = user->acl;
        break;
    case S_enableacl:
        v.pval = user->enableacl;
        break;
    case S_remoteacl:
        v.pval = user->remoteacl;
        break;
#endif

    case S_pap:
	v.pval = user->pap;
	break;

    case S_opap:
	v.pval = user->opap;
	break;

    case S_message:
	v.pval = user->msg;
	break;

    case S_svc:
	v.pval = user->svcs;
	break;

    case S_before:
	v.pval = user->before_author;
	break;

    case S_after:
	v.pval = user->after_author;
	break;

    case S_svc_dflt:
	v.intval = user->svc_dflt;
	break;

#ifdef MAXSESS
    case S_maxsess:
	v.intval = user->maxsess;
	break;
#endif 

    case S_nopasswd:
	v.intval = user->nopasswd;
	break;
	
    case S_time:
	v.pval = user->time;
	break;

    default:
	report(LOG_ERR, "get_value (user): unknown field %d", field);
	break;
    }
    return (v);
}

/* For host , find value of field. Doesn't recursive */
VALUE
get_hvalue(host, field)
HOST *host;
int field;
{
    VALUE v;
    v.intval = 0;
    if(!host) {
	parse_error("get_hvalue: illegal host");
        return (v);
    }
    switch (field) {
	case S_name:
        v.pval = host->name;
        break;
	
	case S_key:
	v.pval = host->key;
    	break;

	case S_type:
	v.pval = host->type;
	break;

	case S_prompt:
	v.pval = host->prompt;
	break;
	
	case S_enable:
	v.pval = host->enable;
	break;

/* Added by Olivier BEDOUET 2011/14/4 */
#ifdef ACLS
	case S_acl:
	v.pval = host->acl;
	break;
#endif
/* End */

	default:
        report(LOG_ERR, "get_hvalue: unknown field %d", field);
        break;
    }
    return (v);
}


/* For each user, check she doesn't circularly reference a
   group. Return 1 if it does */
int
circularity_check(void)
{
    USER *user, *entry, *group;
    USER **users = (USER **) hash_get_entries(usertable);
    USER **groups = (USER **) hash_get_entries(grouptable);
    USER **p, **q;

    /* users */
    for (p = users; *p; p++) {
	user = *p;

	if (debug & DEBUG_PARSE_FLAG)
	    report(LOG_DEBUG, "circularity_check: user=%s", user->name);

	/* Initialise all groups "seen" flags to zero */
	for (q = groups; *q; q++) {
	    group = *q;
	    group->flags &= ~FLAG_SEEN;
	}

	entry = user;

	while (entry) {
	    /* check groups we are a member of */
	    char *groupname = entry->member;

	    if (debug & DEBUG_PARSE_FLAG)
		report(LOG_DEBUG, "\tmember of group %s",
		       groupname ? groupname : "<none>");


	    /* if not a member of any groups, go on to next user */
	    if (!groupname)
		break;

	    group = (USER *) hash_lookup(grouptable, groupname);
	    if (!group) {
		report(LOG_ERR, "%s=%s, group %s does not exist",
		       (entry->flags & FLAG_ISUSER) ? "user" : "group",
		       entry->name, groupname);
		s_free(users);
		s_free(groups);
		return (1);
	    }
	    if (group->flags & FLAG_SEEN) {
		report(LOG_ERR, "recursively defined groups");

		/* print all seen "groups" */
		for (q = groups; *q; q++) {
		    group = *q;
		    if (group->flags & FLAG_SEEN)
			report(LOG_ERR, "%s", group->name);
		}
		s_free(users);
		s_free(groups);
		return (1);
	    }
	    group->flags |= FLAG_SEEN;	/* mark group as seen */
	    entry = group;
	}
    }
    s_free(users);
    s_free(groups);
    return (0);
}


/* Return a value for a group or user (isuser says if
   this name is a group or a user name).

   If no value exists, and recurse is true, also check groups we are a
   member of, recursively.

   Returns void * because it can return a string or a node pointer
   (should really return a union pointer).
*/
VALUE
cfg_get_value(name, isuser, attr, recurse)
char *name;
int isuser, attr, recurse;
{
    USER *user, *group;
    VALUE value;

    value.pval = NULL;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_value: name=%s isuser=%d attr=%s rec=%d",
	       name, isuser, codestring(attr), recurse);

    /* find the user/group entry */

    user = (USER *) hash_lookup(isuser ? usertable : grouptable, name);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_value: no user/group named %s", name);
	return (value);
    }

    /* found the entry. Lookup value from attr=value */
    value = get_value(user, attr);

    if (value.pval || !recurse) {
	return (value);
    }
    /* no value. Check containing group */
    if (user->member)
	group = (USER *) hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_value: recurse group = %s",
		   group->name);

	value = get_value(group, attr);

	if (value.pval) {
	    return (value);
	}
	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *) hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    /* no value for this user or her containing groups */
    value.pval = NULL;
    return (value);
}


/* Wrappers for cfg_get_value */
int cfg_get_intvalue(name, isuser, attr, recurse)
char *name;
int isuser, attr, recurse;
{
    int val = cfg_get_value(name, isuser, attr, recurse).intval;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_intvalue: returns %d", val);
    return(val);
}

char *cfg_get_pvalue(name, isuser, attr, recurse)
char *name;
int isuser, attr, recurse;
{
    char *p = cfg_get_value(name, isuser, attr, recurse).pval;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_pvalue: returns %s", 
	       p ? p : "NULL");
    return(p);
}

/* For getting host values */
VALUE
cfg_get_hvalue(name, attr)
char *name;
int attr;
{
    HOST *host;
    VALUE value;
    int i;
#ifdef ACLS
    VALUE acl_name;
#endif

    value.pval = NULL;
    if (debug & DEBUG_CONFIG_FLAG)
        report(LOG_DEBUG, "cfg_get_hvalue: name=%s attr=%s ",
               name, codestring(attr));
    
    /* find the host entry in hash table */

    host = (HOST *) hash_lookup( hosttable, name);

    if (!host) 
    {
        if (debug & DEBUG_CONFIG_FLAG)
            report(LOG_DEBUG, "cfg_get_hvalue: no host named %s", name);

/* Added by Olivier BEDOUET 2011/04/14 */
#ifdef ACLS
	if (attr==S_acl)	/* To avoid unfinite search ! */
	    return(value);

	if (debug & DEBUG_CONFIG_FLAG)
            report(LOG_DEBUG, "cfg_get_hvalue: trying to search host %s through ACL", name);

	/* For each host entry, try to look if an ACL match the name */
	i=0;
	while(i < HASH_TAB_SIZE)
	{
	    host=hash_get_entry(hosttable, i);
	    if (host != NULL)
	    {
		acl_name=get_hvalue(host, S_acl);
		if (acl_name.pval)
		{
		    /* Found a host with an ACL */
		    if (cfg_acl_check(acl_name.pval, name)==S_permit)
			i=HASH_TAB_SIZE;	/* Host is matching ACL */
		}
	    }
	    i++;
	}
	if (i==HASH_TAB_SIZE)
	    return(value);	/* did not find match */
	
#endif
/* End */
    }

    /* found the entry. Lookup value from attr=value */
    value = get_hvalue(host, attr);

    if (value.pval) {
        return (value);
    }
    /* No any value for this host */    
    value.pval = NULL;
    return (value);
}

/* Wrappers for cfg_get_hvalue */
char *
cfg_get_phvalue(name, attr)
char *name;
int attr;
{
    char *p = cfg_get_hvalue(name, attr).pval;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_phvalue: returns %s", 
	       p ? p : "NULL");
    return(p);
}

/*
   Read the config file and do some basic sanity checking on
   it. Return 1 if we find any errors. */

cfg_read_config(cfile)
char *cfile;
{
    sym_line = 1;

    if ((cf = fopen(cfile, "r")) == NULL) {
	report(LOG_ERR, "read_config: fopen() error for file %s %s, exiting",
	       cfile, sys_errlist[errno]);
	return (1);
    }
    if (parse_decls() || sym_error) {
	fclose(cf);
	return (1);
    }

    if (circularity_check()) {
	fclose(cf);
	return (1);
    }

    fclose(cf);
    return (0);
}

/* return 1 if user exists, 0 otherwise */
int
cfg_user_exists(username)
char *username;
{
    USER *user = (USER *) hash_lookup(usertable, username);

    return (user != NULL);
}

#ifdef ACLS
/*
 * check the acl against the provided ip.  return S_permit (succeed) if the
 * ip matches a permit, else S_deny (fail) if it matches a deny or does not
 * match any of the entries.
 */
int
cfg_acl_check(char *aclname, char *ip)
{
    NODE *next;
    ACL *acl;

    if (aclname == NULL || ip == NULL)
    {
	report(LOG_ERR, "cfg_acl_check(): bad parms !!!");
        return(S_deny);
    }

    acl = (ACL *) hash_lookup(acltable, aclname);

    if (debug & DEBUG_AUTHEN_FLAG)
        report(LOG_DEBUG, "cfg_acl_check(%s, %s)", aclname, ip);

    if (acl == NULL) {
        report(LOG_ERR, "non-existent acl reference %s", aclname);
        return(S_deny);
    }

    next = acl->nodes;
    while (next) {
        if (regexec(next->value1, ip)) {
            if (debug & DEBUG_AUTHEN_FLAG)
                report(LOG_DEBUG, "ip %s matched %s regex %s of acl filter %s",
                        ip, next->type == S_deny ? "deny" : "permit",
                        next->value, aclname);
            return(next->type);
        }
        next = next->next;
    }

    /* default is fail (implicit deny) - ie: fell off the end */
    if (debug & DEBUG_AUTHEN_FLAG)
        report(LOG_DEBUG, "ip %s did not match in acl filter %s", ip, aclname);
    return(S_deny);
}
#endif

/* return expiry string of user. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
char *cfg_get_expires(char *username, int recurse)
{
    return (cfg_get_pvalue(username, TAC_IS_USER, S_expires, recurse));
}

/* return time string of user. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
char *cfg_get_timestamp(char *username, int recurse)
{
    return (cfg_get_pvalue(username, TAC_IS_USER, S_time, recurse));
}


/* return password string of user. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
char *cfg_get_login_secret(char *user, int recurse)
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_login, recurse));
}

/* return value of the nopasswd field. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
int cfg_get_user_nopasswd(char *user, int recurse)
{
    return (cfg_get_intvalue(user, TAC_IS_USER, S_nopasswd, recurse));
}

/* return user's secret. If none, try groups she is a member
   on, and so on, recursively if recurse is non-zero */
char *cfg_get_arap_secret(char *user, int recurse)
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_arap, recurse));
}

char *cfg_get_chap_secret(char *user, int recurse)
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_chap, recurse));
}

#ifdef MSCHAP
char *cfg_get_mschap_secret(char *user, int recurse)
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_mschap, recurse));
}
#endif /* MSCHAP */

char *cfg_get_pap_secret(char *user, int recurse)
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_pap, recurse));
}

char *cfg_get_opap_secret(char *user, int recurse)
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_opap, recurse));
}

/* return the global password for the user (or the group, etc.) */
char *cfg_get_global_secret(char *user, int recurse)
{
    return (cfg_get_pvalue(user, TAC_IS_USER, S_global, recurse));
}

#ifdef USE_PAM
/* Return a pointer to a node representing a PAM Service name */
char *cfg_get_pam_service(char *user, int recurse)
{
    char *cfg_passwd;
    char *p;   

    cfg_passwd = cfg_get_pap_secret(user, recurse);
 
    if (!cfg_passwd) {
    	cfg_passwd = cfg_get_global_secret(user, recurse);
    }
 
    if (!cfg_passwd && !cfg_user_exists(user)) {
        cfg_passwd = cfg_get_authen_default();
        switch (cfg_get_authen_default_method()) {
		case (S_pam): 
			if (debug & DEBUG_AUTHOR_FLAG)
                        report(LOG_DEBUG, "Get Default PAM Service :%s",cfg_passwd);
			return(cfg_passwd);
			break;
		default:
			if (debug & DEBUG_AUTHOR_FLAG)
                        report(LOG_DEBUG, "I havent find any PAM Service!!");
			return(NULL);/* Haven't any PAM Service!! */
	}
    }

    p=tac_find_substring("pam ", cfg_passwd);

    if(p) {  /* We find PAM services */
	if (debug & DEBUG_AUTHOR_FLAG)
		report(LOG_DEBUG, "I get PAM sevice:%s",p);
        return (p);
    }

    if (debug & DEBUG_AUTHOR_FLAG)
	report(LOG_DEBUG, "No any PAM Sevice");

    return(NULL);
}

#endif /* For PAM */
	


/* Return a pointer to a node representing a given service
   authorization, taking care of recursion issues correctly. Protocol
   is only read if the type is N_svc_ppp. svcname is only read if type
   is N_svc.
*/

NODE *cfg_get_svc_node(username, type, protocol, svcname, recurse)
char *username;
int type;
char *protocol, *svcname;
int recurse;
{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, 
	       "cfg_get_svc_node: username=%s %s proto=%s svcname=%s rec=%d",
	       username, 
	       cfg_nodestring(type), 
	       protocol ? protocol : "", 
	       svcname ? svcname : "", 
	       recurse);

    /* find the user/group entry */
    user = (USER *) hash_lookup(usertable, username);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: no user named %s", username);
	return (NULL);
    }

    /* found the user entry. Find svc node */
    for(svc = (NODE *) get_value(user, S_svc).pval; svc; svc = svc->next) {

	if (svc->type != type) 
	    continue;

	if (type == N_svc_ppp && !STREQ(svc->value1, protocol)) {
	    continue;
	}

	if (type == N_svc && !STREQ(svc->value1, svcname)) {
	    continue;
	}

	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, 
		   "cfg_get_svc_node: found %s proto=%s svcname=%s",
		   cfg_nodestring(type), 
		   protocol ? protocol : "", 
		   svcname ? svcname : "");

	return(svc);
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: returns NULL");
	return (NULL);
    }

    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *) hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_svc_node: recurse group = %s",
		   group->name);

	for(svc = (NODE *) get_value(group, S_svc).pval; svc; svc = svc->next) {

	    if (svc->type != type) 
		continue;

	    if (type == N_svc_ppp && !STREQ(svc->value1, protocol)) {
		continue;
	    }

	    if (type == N_svc && !STREQ(svc->value1, svcname)) {
		continue;
	    }

	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG, 
		       "cfg_get_svc_node: found %s proto=%s svcname=%s",
		       cfg_nodestring(type), 
		       protocol ? protocol : "", 
		       svcname ? svcname : "");

	    return(svc);
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *) hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_svc_node: returns NULL");

    /* no matching svc node for this user or her containing groups */
    return (NULL);
}

/* Return a pointer to the node representing a set of command regexp
   matches for a user and command, handling recursion issues correctly */
NODE *cfg_get_cmd_node(name, cmdname, recurse)
char *name, *cmdname;
int recurse;
{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_cmd_node: name=%s cmdname=%s rec=%d",
	       name, cmdname, recurse);

    /* find the user/group entry */
    user = (USER *) hash_lookup(usertable, name);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: no user named %s", name);
	return (NULL);
    }
    /* found the user entry. Find svc node */
    svc = (NODE *) get_value(user, S_svc).pval;

    while (svc) {
	if (svc->type == N_svc_cmd && STREQ(svc->value, cmdname)) {
	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG, "cfg_get_cmd_node: found cmd %s %s node",
		       cmdname, cfg_nodestring(svc->type));
	    return (svc);
	}
	svc = svc->next;
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: returns NULL");
	return (NULL);
    }
    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *) hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_get_cmd_node: recurse group = %s",
		   group->name);

	svc = get_value(group, S_svc).pval;

	while (svc) {
	    if (svc->type == N_svc_cmd && STREQ(svc->value, cmdname)) {
		if (debug & DEBUG_CONFIG_FLAG)
		    report(LOG_DEBUG, "cfg_get_cmd_node: found cmd %s node %s",
			   cmdname, cfg_nodestring(svc->type));
		return (svc);
	    }
	    svc = svc->next;
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *) hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_get_cmd_node: returns NULL");

    /* no matching cmd node for this user or her containing groups */
    return (NULL);
}

/* Return an array of character strings representing configured AV
 * pairs, given a username and a service node. 
 *
 * In the AV strings returned, manipulate the separator character to
 * indicate which args are optional and which are mandatory.
 *
 * Lastly, indicate what default permission was configured by setting
 * denyp */

char **cfg_get_svc_attrs(svcnode, denyp)
NODE *svcnode;
int *denyp;
{
    int i;
    NODE *node;
    char **args;

    *denyp = 1;

    if (!svcnode)
	return (NULL);

    *denyp = (svcnode->dflt == S_deny);

    i = 0;
    for (node = svcnode->value; node; node = node->next)
	i++;

    args = (char **) tac_malloc(sizeof(char *) * (i + 1));

    i = 0;
    for (node = svcnode->value; node; node = node->next) {
	char *arg = tac_strdup(node->value);
	char *p = index(arg, '=');

	if (p && node->type == N_optarg)
	    *p = '*';
	args[i++] = arg;
    }
    args[i] = NULL;
    return (args);
}


int cfg_user_svc_default_is_permit(user)
char *user;
{
    int permit = cfg_get_intvalue(user, TAC_IS_USER, S_svc_dflt,
			       TAC_PLUS_RECURSE);

    switch (permit) {
    default:			/* default is deny */
    case S_deny:
	return (0);
    case S_permit:
	return (1);
    }
}

int cfg_no_user_permitted(void)
{
    if (no_user_dflt == S_permit)
	return (1);
    return (0);
}

char *cfg_get_authen_default(void)
{
    return (authen_default);
}

/* For describe authentication method(pam,file,db..etc) */
int cfg_get_authen_default_method(void)
{
   return (authen_default_method);
}


/* Return 1 if this user has any ppp services configured. Used for
   authorizing ppp/lcp requests */
int cfg_ppp_is_configured(username, recurse)
char *username;
int recurse;
{
    USER *user, *group;
    NODE *svc;

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_ppp_is_configured: username=%s rec=%d",
	       username, recurse);

    /* find the user/group entry */
    user = (USER *) hash_lookup(usertable, username);

    if (!user) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: no user named %s", 
		   username);
	return (0);
    }

    /* found the user entry. Find svc node */
    for(svc = (NODE *) get_value(user, S_svc).pval; svc; svc = svc->next) {

	if (svc->type != N_svc_ppp) 
	    continue;

	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: found svc ppp %s node",
		   svc->value1);
	
	return(1);
    }

    if (!recurse) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: returns 0");
	return (0);
    }

    /* no matching node. Check containing group */
    if (user->member)
	group = (USER *) hash_lookup(grouptable, user->member);
    else
	group = NULL;

    while (group) {
	if (debug & DEBUG_CONFIG_FLAG)
	    report(LOG_DEBUG, "cfg_ppp_is_configured: recurse group = %s",
		   group->name);

	for(svc = (NODE *) get_value(group, S_svc).pval; svc; svc = svc->next) {

	    if (svc->type != N_svc_ppp)
		continue;

	    if (debug & DEBUG_CONFIG_FLAG)
		report(LOG_DEBUG, "cfg_ppp_is_configured: found svc ppp %s node",
		       svc->value1);
	
	    return(1);
	}

	/* still nothing. Check containing group and so on */

	if (group->member)
	    group = (USER *) hash_lookup(grouptable, group->member);
	else
	    group = NULL;
    }

    if (debug & DEBUG_CONFIG_FLAG)
	report(LOG_DEBUG, "cfg_ppp_is_configured: returns 0");

    /* no PPP svc nodes for this user or her containing groups */
    return (0);
}

/* For getting host key */
char *cfg_get_host_key(host)
char *host;
{
    return (cfg_get_phvalue(host, S_key));
}

/* For getting host prompt */
char *cfg_get_host_prompt(host)
char *host;
{
    return (cfg_get_phvalue(host, S_prompt));
}

/* For getting host enable */
char *cfg_get_host_enable(host)
char *host;
{
    return (cfg_get_phvalue(host, S_enable));
}

