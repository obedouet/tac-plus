/* 
		This is Database Functions header file 
*/

#if defined(DB)

/* The databases  recognized by this definition */
#define DEFINED_DB {"null","mysql","pgsql"}

#define SQLCMDL 1024

#if defined(DB_MYSQL)
#define MYAUTHSQL "SELECT %s FROM %s WHERE %s=\"%s\""
#define MYACCTSQL "INSERT INTO %s (usern,s_name,c_name,elapsed_time,bytes_in,bytes_out,fin_t) VALUES (\"%s\",\"%s\",\"%s\",%s,%s,%s,NOW())"
#endif /* DB_MYSQL */

#if defined(DB_PGSQL)
#define PWLEN   13
#define PGAUTHSQL "SELECT %s FROM %s WHERE %s='%s'"
#define PGACCTSQL "INSERT INTO %s (usern,s_name,c_name,elapsed_time,bytes_in,bytes_out,fin_t) VALUES ('%s','%s','%s',%s,%s,%s,NOW())"
#endif /* DB_PGSQL */

#endif /* DB */
