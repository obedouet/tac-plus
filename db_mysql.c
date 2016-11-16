#if defined(DB_MYSQL) && defined(DB)
/*

		Writen by Devrim SERAL(devrim@gazi.edu.tr)
     This program writen for MySQL Authentication and Accounting Propose

License: This code is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2, or (at your option) any later version.

*/

#include "tac_plus.h"
#include <stdio.h>
#include <mysql.h>
#include "db.h"

MYSQL *mysqldb;
MYSQL_RES *res;
MYSQL_ROW row;
MYSQL_FIELD *table_field;

/* 		This MySQL Authentication Function		*/

int mysql_db_verify(user, users_passwd, db_user, db_password,
	db_hostname,db_name, db_table, dbfield_name, dbfield_passwd)


char *user, *users_passwd;      /* Username and gived password   */
char *db_user;                  /* db's parameters               */
char *db_password;
char *db_hostname;
char *db_name;
char *db_table;
char *dbfield_name;
char *dbfield_passwd;

{

char *real_passwd;
char *mysqlcmd;
int sql_len;

   if (debug & DEBUG_AUTHEN_FLAG)
	report(LOG_DEBUG, "MySQL: verify %s", user);
	
/* Connect database server */

   if ( !( mysql_connect(mysqldb,db_hostname,db_user,db_password) ) )
	{
   	        if (debug & DEBUG_AUTHEN_FLAG)
		    report(LOG_DEBUG, "MySQL: cannot connect as %s", db_user);
		return(0);
	}

/*Select tacacs db */

    if ( mysql_select_db(mysqldb,db_name) )
	{
   		if (debug & DEBUG_AUTHEN_FLAG)
		   report(LOG_DEBUG, "MySQL: cannot find database named %s",db_name);
        	return(0);
	}

/* Check select string length */

sql_len=strlen(dbfield_passwd)+strlen(dbfield_name)+
	strlen(db_table)+strlen(user)+strlen(MYAUTHSQL);

  if ( sql_len>= SQLCMDL )
        {
        	if (debug & DEBUG_AUTHEN_FLAG)
		     report(LOG_DEBUG, "MySQL: Sql cmd exceed alowed limits");
        	return(0);
        }

/* Prepare select string */

if ((mysqlcmd=(char *) s_malloc(sql_len)) == NULL ) {
	if (debug & DEBUG_AUTHEN_FLAG)
		report(LOG_ERR, "mysql_db_verify: mysqlcmd malloc error");
	return(0);
}

sprintf(mysqlcmd,MYAUTHSQL,dbfield_passwd,db_table,dbfield_name,user);

/*  Query database */

    if (mysql_query(mysqldb,mysqlcmd))
	{
	if (debug & DEBUG_AUTHEN_FLAG)
		report(LOG_DEBUG, "MySQL: cannot query database ");
    	s_free(mysqlcmd);
        return(0);
	}

    s_free(mysqlcmd);
    
    if (!(res = mysql_store_result(mysqldb)))
	{
	if (debug & DEBUG_AUTHEN_FLAG)
  		report(LOG_DEBUG, "MySQL: cannot store result");
        return(0);
	}  
   
   if(!(row = mysql_fetch_row(res)))
	{
	if (debug & DEBUG_AUTHEN_FLAG)
        	report(LOG_DEBUG, "MySQL: cannot fetch row");
        return(0);
        }  
  
   if(strlen(row[0]) <= 0 )
        {
	if (debug & DEBUG_AUTHEN_FLAG)
        	report(LOG_DEBUG, "MySQL: DB passwd entry is NULL");
        return(0);
        }
   /* Allocate memory for real_passwd */
   if ((real_passwd=(char *) s_malloc(strlen(row[0])+1)) == NULL ) {
   
        if (debug & DEBUG_AUTHEN_FLAG)
                report(LOG_ERR, "mysql_db_verify: real_passwd malloc error");
        return(0);
   }

	strcpy(real_passwd,row[0]);
 
   if (!mysql_eof(res))
	{
	if (debug & DEBUG_AUTHEN_FLAG)
        	report(LOG_DEBUG, "MySQL:  Result not end!!");
        return(0);
        }

    mysql_free_result(res);
    mysql_close(mysqldb);
  
if (debug & DEBUG_AUTHEN_FLAG)   
     report(LOG_DEBUG, "MySQL: verify password '%s' to DES encrypted string '%s'", users_passwd, real_passwd);

    /* Try to verify the password */
    if (!des_verify(users_passwd, real_passwd)) {
        s_free(real_passwd);
	return (0);
    }
    s_free(real_passwd);
    return (1); /* Return 1 if verified, 0 otherwise. */
} 
/* end of MySQL authentication */

/* 		This MySQL Accounting Function			*/

int 
mysql_db_acct(db_user,db_password,db_hostname,db_name,
	      db_table,s_name,c_name,a_username,
	      elapsed_time,bytes_in,bytes_out)

char *db_user;			/* db's parameters		*/
char *db_password;
char *db_hostname;
char *db_name;
char *db_table;
char *s_name, *c_name,*a_username,*elapsed_time,*bytes_in,*bytes_out;

{

char *mysqlcmd;
int sql_len;
	
/* Connect database server */

   if (!(mysql_connect(mysqldb,db_hostname,db_user,db_password)))
	{
	if (debug & DEBUG_ACCT_FLAG)
		report(LOG_DEBUG, "MySQL: cannot connect as %s", db_user);
		return(0);
	}

/*Select tacacs db */

    if (mysql_select_db(mysqldb,db_name))
	{
	if (debug & DEBUG_ACCT_FLAG)
	   report(LOG_DEBUG, "MySQL: cannot find database named %s",db_name);
           return(0);
	}

/* Check buffer overflow for select string */
sql_len=strlen(db_table)+strlen(a_username)+
	strlen(s_name)+strlen(c_name)+strlen(elapsed_time)+
	strlen(bytes_in)+strlen(bytes_out)+strlen(MYACCTSQL);  

if ( sql_len >= SQLCMDL )
        {
        if (debug & DEBUG_ACCT_FLAG)
		report(LOG_DEBUG, "MySQL: Sql cmd exceed alowed limits");
        	return(0);
        }
 

/* Prepare select string */
if ((mysqlcmd = (char *) s_malloc(sql_len)) == NULL ) {
	if (debug & DEBUG_ACCT_FLAG)
		report(LOG_ERR, "mysql_db_acct: mysqlcmd malloc error");
	return(0);
}

sprintf(mysqlcmd,MYACCTSQL,db_table,a_username,s_name,c_name,elapsed_time,bytes_in,bytes_out);

/*  Query database */

    if (mysql_query(mysqldb,mysqlcmd))
	{
	if (debug & DEBUG_ACCT_FLAG)
		report(LOG_DEBUG, "MySQL: cannot query database");
	s_free(mysqlcmd);
	return(0);
        }

	s_free(mysqlcmd);

/* Check if accounting is sucess */
    if ( mysql_affected_rows( mysqldb ) < 0 )
	{
	if (debug & DEBUG_ACCT_FLAG)
		report(LOG_DEBUG, "MySQL: Insert isn't sucess");
        return(0);
        }
	return (1); /* Return 1 if verified, 0 otherwise. */
}
/* end of MySQL accounting */
#endif
