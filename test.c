/*
 * =====================================================================================
 *
 *       Filename:  test.c
 *
 *    Description:  cname 
 *
 *        Version:  1.0
 *        Created:  2013年02月18日 11时40分53秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  hss (mn), housansan@yeah.net
 *        Company:  no
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int main()
{
	putenv("GATEWAY_INTERFACE=CGI/1.1");
	putenv("SCRIPT_FILENAME=/home/administrator/code/tinyweb/webroot/cgi/bb.php");
	putenv("QUERY_STRING=ffff");
	putenv("REQUEST_METHOD=GET");
	putenv("REDIRECT_STATUS=true");
	putenv("SERVER_PROTOCOL=HTTP/1.1");
	putenv("REMOTE_HOST=127.0.0.1");
	execl("/usr/bin/php-cgi","php-cgi",NULL);
	//execl("/bin/ls","ls","-al","/etc/passwd",(char * )0);
}
