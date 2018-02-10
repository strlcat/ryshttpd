/*
 * ryshttpd config file.
 *
 * NOTE: all the config variables specified here
 * can be freely overriden from command line.
 * This file provides some usable defaults.
 */

/* Use libmagic. Without it will include small static mime table based on regex file names. */
/* #define WITH_LIBMAGIC */

/* Use TLS with embedded TLSE. This option blows binary size a bit. */
/* #define WITH_TLS */

/* default listening port (both IPv4 and IPv6) */
#define RH_DEFAULT_PORT "8079"
#ifdef WITH_TLS
/* default tls listening port (both IPv4 and IPv6) */
#define RH_DEFAULT_TLS_PORT "4432"
#endif
/* default "Server:" and pages footer server identifier */
#define RH_DEFAULT_IDENT PROGRAM_NAME
/* default log format */
#define RH_DEFAULT_LOG_FORMAT "[%{client_ipaddr}]:%{clinfo_port} [%{req_time}] "	\
	"%{pid} #%{req_number} %{hdr_host} \"%{req_line}\" "				\
	"%{req_status} %{req_filedir}\"%{req_realpath}\" "				\
	"%{req_recv}/%{req_sent} %{req_range_start}-%{req_range_end}/%{req_filesize} "	\
	"\"%{hdr_user_agent}\" \"%{hdr_referer}\""
/* index file names which are considered to be shown instead of directory listing */
#define RH_DEFAULT_INDEXES "index.html:index.cgi"
/* htaccess default file name */
#define RH_DEFAULT_HTACCESS_NAME ".htaccess"
/* "plain CGI" file names (regex) to be executed. */
#define RH_DEFAULT_CGI_EXECS "/(cgi/[^/]*\\.cgi|.*/index\\.cgi)"
/* "NoHeaders CGI" file names (regex) to be executed as such. */
#define RH_DEFAULT_NHCGI_EXECS "/nhcgi/[^/]*\\.cgi"
/* "CGI ends head response" file names (regex) to be executed as such. */
#define RH_DEFAULT_CGIEH_EXECS "/cgieh/[^/]*\\.cgi"
/* default CGI path */
#define RH_DEFAULT_CGI_PATH "/bin:/sbin:/usr/bin:/usr/sbin"
/* limit connections per single /32 IPv4 or /64 IPv6 subnet */
#define RH_DEFAULT_CONNECTIONS_LIMIT 5
/* first request timeout */
#define RH_DEFAULT_REQUEST_TIMEOUT 15
/* keep alive timeout */
#define RH_DEFAULT_KEEPALIVE_TIMEOUT 30
/* max. nr of keep alive requests per single client server */
#define RH_DEFAULT_KEEPALIVE_REQUESTS 50
