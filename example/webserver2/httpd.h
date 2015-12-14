#ifndef _HTTPD_H_
#define _HTTPD_H_

#define DEFAULT_ROOT_DIRECTORY "/var/www"
#define DEFAULT_BIND_ADDRESS OFP_INADDR_ANY
#define DEFAULT_BIND_PORT 2048
#define DEFAULT_BACKLOG 100

int setup_webserver(char *root_dir, char *laddr, uint16_t lport);

#endif
