/*
 * ryshttpd config file.
 *
 * NOTE: all the config variables specified here
 * can be freely overriden from command line.
 * This file provides some usable defaults.
 */

/* Use libmagic. Without it will include small static mime table based on regex file names. */
/* #define WITH_LIBMAGIC */

/* default listening port (both IPv4 and IPv6) */
#define RH_DEFAULT_PORT "8079"
/* default "Server:" and pages footer server identifier */
#define RH_DEFAULT_IDENT PROGRAM_NAME
/* default log format */
#define RH_DEFAULT_LOG_FORMAT "[%{client_ipaddr}]:%{clinfo_port} [%{req_time}] "	\
	"%{pid} #%{req_number} %{hdr_host} \"%{req_line}\" "				\
	"%{req_status} %{req_filedir}\"%{req_realpath}\" "				\
	"%{req_recv}/%{req_sent} %{req_range_start}-%{req_range_end}/%{req_filesize} "	\
	"\"%{hdr_user_agent}\" \"%{hdr_referer}\""
/* index file names which are considered to be shown instead of directory listing */
#define RH_DEFAULT_INDEXES "index\\.(htm(|l)|txt|(|nh|eh)cgi|sh|pl)"
/* htaccess default file name */
#define RH_DEFAULT_HTACCESS_NAME ".htaccess"
/* "plain CGI" file names (regex) to be executed. */
#define RH_DEFAULT_CGI_EXECS "/(cgi/[^/]*\\.cgi|(|.*/)index\\.cgi)"
/* "NoHeaders CGI" file names (regex) to be executed as such. */
#define RH_DEFAULT_NHCGI_EXECS "/(nhcgi/[^/]*\\.cgi|(|.*/)index\\.nhcgi)"
/* "CGI ends head response" file names (regex) to be executed as such. */
#define RH_DEFAULT_CGIEH_EXECS "/(cgieh/[^/]*\\.cgi|(|.*/)index\\.ehcgi)"
/* default CGI path */
#define RH_DEFAULT_CGI_PATH "/bin:/sbin:/usr/bin:/usr/sbin"
/* limit connections per single /32 IPv4 or /64 IPv6 subnet */
#define RH_DEFAULT_CONNECTIONS_LIMIT 5
/* limit total number of client connections for any subnet types */
#define RH_DEFAULT_ALL_CONNECTIONS_LIMIT 1000
/* first request timeout */
#define RH_DEFAULT_REQUEST_TIMEOUT 15
/* receive (read from client) timeout, 0 to disable */
#define RH_DEFAULT_RECEIVE_TIMEOUT 60
/* send (write to client) timeout, 0 to disable */
#define RH_DEFAULT_SEND_TIMEOUT 60
/* keep alive timeout */
#define RH_DEFAULT_KEEPALIVE_TIMEOUT 30
/* max. nr of keep alive requests per single client server */
#define RH_DEFAULT_KEEPALIVE_REQUESTS 50
