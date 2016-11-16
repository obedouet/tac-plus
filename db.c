/*
     Verify that this user/password is valid per a database.
     Return 1 if verified, 0 otherwise.
     
     Format of connection string (look like internet URL):

       db://user:password@hostname/table?name&passwd

     Example connect to Oracle RDBMS at user 'roger' with password
     'tiger', to 'host.domain.com' database server, fields name in
     table is 'name' and 'passwd' in 'oshadow' table:

       oracle://roger:tiger@host.domain.com/oshadow?name&passwd

     DONE:
     12-nov-1998 Created
                 Add DB support to 'login = db <string>'
     14-nov-1998 Change Tacacs+ version from 0.95 to 3.0.9
     18-nov-1998 Added code for Oracle [version 8.0.5]
     27-nov-1998 Tested with 30'000 usernames Oracle database
                 Added DB support to global configuration
                 'default authentication = db <string>'
     28-nov-1998 Added code for NULL database %)
     
     FUTURE:
     Make *_db_verify() the functions is reenterable
     More security for connection to database
     GDBM support
     Separate debug logging
     Perfomance testing on 10000 records in Oracle database
     (in guide sayd about 3 auth/sec on Ultra 2 - hmm)
     
     -------------------------------------------------------
     fil@artelecom.ru                   http://twister.pp.ru
 
 ****************************************************************************
				    PART II

   I am added some extra extension. Like MySQL and PostgreSQL database support
   And change most of lines for use dynamic memory allocation. db_accounting 
   added by me.
  
   devrim(devrim@gazi.edu.tr)
*/

#if defined(DB)
#include <stdio.h>
#include "tac_plus.h"
#include "db.h"

char *find_attr_value(); 

int
db_verify(user, users_passwd, str_conn)
char *user, *users_passwd;      /* Username and gived password   */
char *str_conn;                 /* String connection to database */
{
    char *buffer;
    char *db_pref, *db_user, *db_password;
    char *db_hostname, *db_table,*db_name,*dbfield_name, *dbfield_passwd;
    int ret;

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "verify %s by database at %s", user, str_conn);

    buffer = db_pref = (char *) s_malloc( strlen(str_conn) + 1 );
    if( buffer == NULL ){
	report(LOG_DEBUG, "Error allocation memory");
        return(0);
    }

    strcpy( buffer, str_conn );

    db_user = (char *)strstr( db_pref, "://" );
    if( db_user == NULL ){
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse db_user");
    	    s_free(buffer);
	    return(0);
    }
    *db_user = '\0'; 

	/* For recognize db authentication database */
    
    if (check_db_type(db_pref)) {
	report(LOG_DEBUG, "%s DB authentication scheme didn't recognize by tac_plus",db_pref);
    	s_free(buffer);
        return(0);
    }

    db_user += 3;

    db_password = (char *)strstr( db_user, ":" );
    if( db_password == NULL ){
        if (debug & DEBUG_PASSWD_FLAG)
    	     report(LOG_DEBUG, "Error parse db_password");
    	s_free(buffer);
        return(0);
    }
    *db_password = '\0';
    db_password++;
    
    db_hostname = (char *)strstr( db_password, "@" );
    if( db_hostname == NULL ){
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse db_hostname");
    	s_free(buffer);
        return(0);
    }
    *db_hostname = '\0';
    db_hostname++;
    
    db_name = (char *)strstr( db_hostname, "/" );
    if( db_name == NULL ){
        if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse db_name");
    	s_free(buffer);
        return(0);
    } 
    *db_name = '\0';
    db_name++;
    
    db_table = (char *)strstr( db_name, "/" );
    if( db_table == NULL ){
        if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse db_table");
    	s_free(buffer);
        return(0);
    } 
    *db_table = '\0';
    db_table++;
    
    dbfield_name = (char *)strstr( db_table, "?" );
    if( dbfield_name == NULL){
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse dbfield_name");
    	s_free(buffer);
        return(0);
    }
    *dbfield_name = '\0';
    dbfield_name++;


    dbfield_passwd = (char *)strstr( dbfield_name, "&" );
    if( dbfield_passwd == NULL){
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse dbfield_passwd");
    	s_free(buffer);
        return(0);
    }
    *dbfield_passwd = '\0';
    dbfield_passwd++;
    

    /* Parse database connection string */
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "db_verify: db_pref=%s, db_user=%s, db_password=%s db_hostname=%s, db_name=%s ,db_table=%s, dbfield_name=%s, dbfield_passwd=%s", db_pref, db_user, db_password, db_hostname, db_name,db_table, dbfield_name, dbfield_passwd);

    /* Check for empty passwords */
   if (users_passwd == NULL || *users_passwd == '\0' ||
        db_password == NULL || *db_password == '\0' ) {
        if (debug & DEBUG_PASSWD_FLAG)
           report(LOG_DEBUG, "One from passwords is empty");
    	s_free(buffer);
	return (0);
    }

    ret = 0;

    /* Run database depend function */
#if defined(DB_ORACLE)
    if (!strcmp(db_pref, "oracle")) {
	ret = oracle_db_verify(
	    user, users_passwd,
	    db_user, db_password, db_hostname, db_table,
	    dbfield_name, dbfield_passwd);
    }
#endif

#if defined(DB_MYSQL)
    if (!strcmp(db_pref, "mysql")) {
	ret = mysql_db_verify(
	    user, users_passwd,
	    db_user, db_password, db_hostname, db_name, db_table,
	    dbfield_name, dbfield_passwd);
    }
#endif

#if defined(DB_PGSQL)
    if (!strcmp(db_pref, "pgsql")) {
	ret = pgsql_db_verify(
	    user, users_passwd,
	    db_user, db_password, db_hostname,db_name, db_table,
	    dbfield_name, dbfield_passwd);
    }
#endif

#if defined(DB_NULL)
    if (!strcmp(db_pref, "null")) {
        ret = null_db_verify(
	    user, users_passwd,
	    db_user, db_password, db_hostname ,db_table,
	    dbfield_name, dbfield_passwd);
    }
#endif

#if defined(DB_GDBM)
    if (!strcmp(db_pref, "gdbm")) {
        gdb_db_verify();
    }
#endif
    s_free(buffer); /* Free unused memory */
    return (ret); /* error */
}


/* Db accounting routine */
int
db_acct(rec)
struct acct_rec *rec;
{
    char *buffer;
    char *db_pref, *db_user, *db_password;
    char *db_hostname, *db_name,*db_table;
    char *a_username,*s_name,*c_name,*elapsed_time,*bytes_in,*bytes_out;
    int ret;

    buffer = db_pref = (char *)s_malloc( strlen(session.db_acct) + 1 );
	
    if( buffer == NULL ){
	report(LOG_DEBUG, "Error allocation memory");
        return(0);
    }

    strcpy( buffer, session.db_acct);

    db_user = (char *)strstr( db_pref, "://" );
    if( db_user == NULL ){
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse db_user");
        s_free(buffer);
	return(0);
    }
    *db_user = '\0'; 

	/* For recognize db accouting database */
    
    if( check_db_type(db_pref) ) {
	report(LOG_DEBUG, "%s DB accounting scheme didn't recognize by tac_plus",db_pref);
        s_free(buffer);
        return(0);
    }

    db_user += 3;

    db_password = (char *)strstr( db_user, ":" );
    if( db_password == NULL ){
        if (debug & DEBUG_PASSWD_FLAG)
    	    report(LOG_DEBUG, "Error parse db_password");
        s_free(buffer);
        return(0);
    }
    *db_password = '\0';
    db_password++;
    
    db_hostname = (char *)strstr( db_password, "@" );
    if( db_hostname == NULL ){
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse db_hostname");
        s_free(buffer);
        return(0);
    }
    *db_hostname = '\0';
    db_hostname++;
    
    db_name = (char *)strstr( db_hostname, "/" );
    if( db_name == NULL ){
        if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse db_name");
        s_free(buffer);
        return(0);
    } 
    *db_name = '\0';
    db_name++;
    
    db_table = (char *)strstr( db_name, "/" );
    if( db_table == NULL ){
        if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Error parse db_table");
        s_free(buffer);
        return(0);
    } 
    *db_table = '\0';
    db_table++;

/* Find some attributes  for accounting */
    a_username=rec->identity->username;
    	if (a_username==NULL ) {
        	if (debug & DEBUG_PASSWD_FLAG) 
			report(LOG_DEBUG,"db_acct: Can't find username!");
        		s_free(buffer);
			return(0);
	}
    s_name=rec->identity->NAS_name;
    	if (s_name==NULL) {
        	if (debug & DEBUG_PASSWD_FLAG) 
			report(LOG_DEBUG,"db_acct: Can't find NAS name!");
        		s_free(buffer);
			return(0);
	}
    c_name=find_attr_value("addr", rec->args, rec->num_args);
    	if (c_name==NULL) {
        	if (debug & DEBUG_PASSWD_FLAG) 
			report(LOG_DEBUG,"db_acct: Can't find client adress!");
	/* Can't find client adress so give NAC_address attribute value */ 
		c_name=rec->identity->NAC_address;
	}
    elapsed_time=find_attr_value("elapsed_time", rec->args, rec->num_args);
    	if (elapsed_time==NULL) {
        	if (debug & DEBUG_PASSWD_FLAG) 
			report(LOG_DEBUG,"db_acct: Can't get elapsed time!");
        		s_free(buffer);
			return(0);
	}
    bytes_in=find_attr_value("bytes_in", rec->args, rec->num_args);
    	if (bytes_in==NULL) bytes_in="0";
    bytes_out=find_attr_value("bytes_out", rec->args, rec->num_args);
    	if (bytes_out==NULL) bytes_out="0";


    /* Parse database connection string */
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "db_verify: db_pref=%s, db_user=%s,db_password=%s , db_hostname=%s, db_name=%s ,db_table=%s ",
        	db_pref, db_user, db_password,
        	db_hostname, db_name,db_table );

    /* Check for empty passwords */
   if (db_user == NULL || db_password == '\0' ) {
        if (debug & DEBUG_PASSWD_FLAG)
           report(LOG_DEBUG, "One from passwords is empty");
        s_free(buffer);
	return (0);
    }

    ret = 0;
    /* Run database depend function */
#if defined(DB_ORACLE)
    if (!strcmp(db_pref, "oracle")) {
	ret = oracle_db_acct(
	    db_user, db_password, db_hostname, db_name, db_table);
    }
#endif

#if defined(DB_MYSQL)
    if (!strcmp(db_pref, "mysql")) {
	ret = mysql_db_acct(
	    db_user, db_password, db_hostname, db_name, db_table,s_name,c_name,a_username,elapsed_time,bytes_in,bytes_out);
    }
#endif

#if defined(DB_PGSQL)
    if (!strcmp(db_pref, "pgsql")) {
        ret = pgsql_db_acct(
            db_user, db_password, db_hostname, db_name, db_table,s_name,c_name,a_username,elapsed_time,bytes_in,bytes_out);
    }
#endif

#if defined(DB_NULL)
    if (!strcmp(db_pref, "null")) {
        ret = null_db_acct(
	    db_user, db_password, db_hostname, db_name, db_table,s_name,c_name,a_username,elapsed_time,bytes_in,bytes_out);
    }
#endif
#if defined(DB_GDBM)
    if (!strcmp(db_pref, "gdbm")) {
        gdb_db_acct();
    }
#endif

    s_free(buffer); /* Free unused memory */
    return (ret); /* error */

}

/* For checking DB type */
int 
check_db_type(db_type)
char *db_type;
{
char *dbp[]=DEFINED_DB;
int ret=1,i;

for (i=0; dbp[i] ; i++ ) {
	if(!strcmp(db_type,dbp[i])) {
		ret=0;
		break;
	}
}
return ret;
}
#endif /* DB */
