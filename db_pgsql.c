#if defined(DB_PGSQL) && defined(DB)

/*
		Writen by Devrim SERAL(devrim@gazi.edu.tr)
	For PostgreSQL Authentication And Accounting Propose
			      28-01-2001

License: This code is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2, or (at your option) any later version.

*/

#include "tac_plus.h"
#include <stdio.h>
#include <libpq-fe.h> 
#include "db.h" 

PGconn     *conn;
PGresult   *res;

/* Clear PgSQL file descriptor and close connection */

int
exit_nicely(PGconn *cn,PGresult *r)
{
    PQclear(r);
    PQfinish(cn);
}

/* 		PgSQL Authentication function 			*/

int 
pgsql_db_verify(user, users_passwd, db_user, db_password,
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
char *pgsqlcmd;
int sql_len;
int nrow;

if (debug & DEBUG_AUTHEN_FLAG)
        report(LOG_DEBUG, "PGSQL: verify %s", user);
	
/* Connect database server */

conn=PQsetdbLogin(db_hostname,NULL,NULL,NULL,db_name,db_user,db_password);

if ( PQstatus(conn) == CONNECTION_BAD ) 
{
    if (debug & DEBUG_AUTHEN_FLAG)
	report(LOG_DEBUG, "PGSQL: Connection to database %s failed", db_name);
	return(0);
}

/* Check select string length */

sql_len=strlen(dbfield_passwd)+strlen(dbfield_name)+strlen(db_table)+strlen(user)+strlen(PGAUTHSQL);

if ( sql_len> SQLCMDL ) {
    if (debug & DEBUG_AUTHEN_FLAG)
       	report(LOG_DEBUG, "PGSQL: Sql cmd exceed alowed limits");
       	return(0);
}

/* Prepare select string */

if ((pgsqlcmd=(char *) s_malloc(sql_len)) == NULL ) {
    if (debug & DEBUG_AUTHEN_FLAG)
	report(LOG_ERR, "pgsql_db_verify: pgsqlcmd malloc error");
	return(0);
}

sprintf(pgsqlcmd,PGAUTHSQL,dbfield_passwd,db_table,dbfield_name,user);

/*  Query database */
res=PQexec(conn,pgsqlcmd);

if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
   if (debug & DEBUG_AUTHEN_FLAG) {
	report(LOG_DEBUG, "PGSQL: cannot query database ");
	report(LOG_DEBUG, "PGSQL: Error message->%s", PQerrorMessage(conn) );
   }
  	s_free(pgsqlcmd);
        exit_nicely(conn,res);
	return(0);
}

s_free(pgsqlcmd);

if( nrow=PQntuples(res)!=1) {  
    if (debug & DEBUG_AUTHEN_FLAG)
        report(LOG_DEBUG, "PGSQL: Have we got more than one password!!");
        exit_nicely(conn,res);
	return(0);
}  
  
if ( PQgetisnull(res,0,PQfnumber(res,dbfield_passwd)) ) {
    if (debug & DEBUG_AUTHEN_FLAG)
        report(LOG_DEBUG, "PGSQL: DB passwd entry is NULL");
        exit_nicely(conn,res);
	return(0);
}

  /* Allocate memory for real_passwd */
    real_passwd=(char *) s_malloc(PWLEN+1);
    strncpy(real_passwd,PQgetvalue(res,0,PQfnumber(res,dbfield_passwd)),PWLEN);
    real_passwd[PWLEN]='\0';
 
exit_nicely(conn,res);
  
if (debug & DEBUG_AUTHEN_FLAG)
    report(LOG_DEBUG, "PGSQL: verify password '%s' to DES encrypted string '%s'", users_passwd, real_passwd);
 
	/* Try to verify the password */
	if (!des_verify(users_passwd, real_passwd)) {
        return (0);
	}

    return (1); /* Return 1 if verified, 0 otherwise. */
}

/*			PGSQL ACCOUNTING function 		*/ 

int pgsql_db_acct(db_user,db_password,db_hostname,db_name,
		  db_table,s_name,c_name,a_username,elapsed_time,
		  bytes_in,bytes_out)

char *db_user;                  /* db's parameters              */
char *db_password;
char *db_hostname;
char *db_name;
char *db_table;
char *s_name, *c_name,*a_username,*elapsed_time,*bytes_in,*bytes_out;

{

char *pgsqlcmd;
int sql_len;

  if (debug & DEBUG_ACCT_FLAG)
	report(LOG_DEBUG, "PGSQL: Accounting for %s begin", a_username);
	
/* Connect database server */

conn=PQsetdbLogin(db_hostname,NULL,NULL,NULL,db_name,db_user,db_password);

if ( PQstatus(conn) == CONNECTION_BAD ) {
   if (debug & DEBUG_ACCT_FLAG) {
	report(LOG_DEBUG, "PGSQL: Connection to database %s failed", db_name);
	report(LOG_DEBUG, "PGSQL: Error message->%s", PQerrorMessage(conn) );
   }
	return(0);
}

/* Check select string length */

sql_len=strlen(db_table)+strlen(a_username)+
	strlen(s_name)+strlen(c_name)+strlen(elapsed_time)+
	strlen(bytes_in)+strlen(bytes_out)+strlen(PGACCTSQL); 

if ( sql_len> SQLCMDL ) {
   if (debug & DEBUG_ACCT_FLAG) 
       	report(LOG_DEBUG, "PGSQL: Sql cmd exceed alowed limits");
   return(0);
}

/* Prepare select string */

if ((pgsqlcmd=(char *) s_malloc(sql_len)) == NULL ) {
   if (debug & DEBUG_ACCT_FLAG) 
	report(LOG_ERR, "pgsql_db_verify: pgsqlcmd malloc error");
   return(0);
}

sprintf(pgsqlcmd,PGACCTSQL,db_table,a_username,s_name,c_name,elapsed_time,bytes_in,bytes_out);
 
/*  Query database */
res=PQexec(conn,pgsqlcmd);

if (!res || PQresultStatus(res) != PGRES_COMMAND_OK )
{
 if (debug & DEBUG_ACCT_FLAG) { 
	report(LOG_DEBUG, "PGSQL: cannot establish database query");
	report(LOG_DEBUG, "PGSQL: Error message->%s", PQerrorMessage(conn) );
}
    	s_free(pgsqlcmd);
        exit_nicely(conn,res);
	return(0);
}

s_free(pgsqlcmd);
    
/* Flush all result and close connection */
exit_nicely(conn,res);

    if (debug & DEBUG_ACCT_FLAG)
	report(LOG_DEBUG, "PGSQL: Accounting for %s finished", a_username);
  
    return (1); /* Return 1 if verified, 0 otherwise. */
}

#endif
