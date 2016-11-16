/*
**  Simple NULL driver for database interface. I created this for testing
**  db_* on my notebook by home. There i dont have Oracle or any database
**  server.                                               Fil/27-nov-1998
**
**  DO_NOT_USE_THIS_FOR_WORK!
*/

#if defined(DB_NULL) && defined(DB)
#include "tac_plus.h"

int null_db_verify(user, users_passwd, db_user, db_password, db_hostname,
	    db_table, dbfield_name, dbfield_passwd)
	    
char *user, *users_passwd;      /* Username and gived password   */
char *db_user;			/* db's parametr's		 */
char *db_password;
char *db_hostname;
char *db_table;
char *dbfield_name;
char *dbfield_passwd;

{
//report(LOG_DEBUG, "DB_NULL(%u) - ok", __LINE__);

    /* Try to verify the password
       Successful if username and password equal */
    if (strcmp(user, users_passwd)) {
	return (0);
    }
    if (debug & DEBUG_PASSWD_FLAG)
       	report(LOG_DEBUG, "DB Null: verify password '%s'", users_passwd);

    return (1); /* Return 1 if verified, 0 otherwise. */
}

/*	Null Database Accounting	*/

int 
null_db_acct(db_user, db_password, db_hostname,db_name,db_table,s_name,c_name,a_username,elapsed_time,bytes_in,bytes_out)
char *db_user;			/* db's parametr's		 */
char *db_password;
char *db_hostname;
char *db_name;
char *db_table;
char *s_name;
char *c_name;
char *a_username;
char *elapsed_time;char *bytes_in;char *bytes_out;
{
report(LOG_INFO,"Db accounting user=%s pass=%s host=%s \
db_name=%s table=%s servern=%s clientn=%s username=%s et=%s bi=%s bo=%s",db_user,db_password,db_hostname,
db_name,db_table,s_name,c_name,a_username,elapsed_time,bytes_in,bytes_out);
return (1);
}
#endif

