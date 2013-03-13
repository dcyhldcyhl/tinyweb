#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "http_session.h"
#include "get_time.h"
#include <sys/wait.h>

/*
 * http 接收处理流程
 */
int http_session(int *connect_fd, struct sockaddr_in *client_addr)
{

	char recv_buf[RECV_BUFFER_SIZE + 1];			/* server socket receive buffer */
	char send_buf[SEND_BUFFER_SIZE + 1];	/* server socket send bufrer */
	char file_buf[FILE_MAX_SIZE + 1];
	memset(recv_buf, '\0', sizeof(recv_buf));
	memset(send_buf, '\0', sizeof(send_buf));
	memset(file_buf, '\0', sizeof(file_buf));

	char uri_buf[URI_SIZE + 1];
	char query_buf[URI_SIZE];
	memset(uri_buf, '\0', sizeof(uri_buf));
	memset(query_buf, '\0', sizeof(query_buf));
	int maxfd;
	fd_set read_set;
	FD_ZERO(&read_set);

	struct timeval timeout;
	timeout.tv_sec = TIME_OUT_SEC;
	timeout.tv_usec = TIME_OUT_USEC;


	int flag = 1;
	int res = 0;
	int read_bytes = 0;
	int send_bytes = 0;
	int file_size = 0;
	char *mime_type;
	int uri_status;
	FD_SET(*connect_fd, &read_set);
	while(flag)
	{
		maxfd = *connect_fd + 1;
		FD_ZERO(&read_set); //每次循环都要清空集合，否则不能检测描述符变化
		FD_SET(*connect_fd, &read_set); //添加描述符
		res = select(maxfd, &read_set, &read_set, NULL, &timeout);
		//printf("RES:%d\n",res);
		switch(res)
		{
			case -1:
			  perror("select() error. in http_sesseion.c");
			  close(*connect_fd);
			  return -1;
			  break;
			case 0:			/* time out, continue to select */
			  //continue;
			  break;
			default:		/* there are some file-descriptor's status changed */
			  if(FD_ISSET(*connect_fd, &read_set))
			  {
				memset(recv_buf, '\0', sizeof(recv_buf));
				if((read_bytes = recv(*connect_fd, recv_buf, RECV_BUFFER_SIZE, 0)) == 0)
				{
					/* client close the connection  */
					return 0;
				}
				else if(read_bytes > 0)		/* there are some data from client */
				{
					if(is_http_protocol(recv_buf) == 0)	/* check is it HTTP protocol */
					{
						fprintf(stderr, "Not http protocol.\n");
						close(*connect_fd);
						return -1;
					}
					else
					{
						//printf("%s\n",recv_buf);
						if(get_uri(recv_buf, uri_buf) == NULL)	/* get the uri from http request head */
						{
							uri_status = URI_TOO_LONG;

						}
						else
						{
							uri_status = get_uri_status(uri_buf);
							printf("URL:%s\n", uri_buf);
							switch(uri_status)
							{
								case FILE_OK:
								  //printf("file ok\n");
								  mime_type = get_mime_type(uri_buf);
								  //printf("mime type: %s\n", mime_type);
								  file_size =  get_file_disk(uri_buf, file_buf,recv_buf);

								  send_bytes = reply_normal_information(send_buf, file_buf, file_size, mime_type);
									
						//		  send(*connect_fd, send_buf, send_bytes, 0);

								  break;
								case FILE_NOT_FOUND:	/* file not found on server */
								  //printf("in switch on case FILE_NOT_FOUND\n");
								  send_bytes = set_error_information(send_buf, FILE_NOT_FOUND);
								  
								  break;	
								case FILE_FORBIDEN:		/* server have no permission to read the request file */
								  break;
								case URI_TOO_LONG:		/* the request uri is too long */

								  break;
								default:
								  break;
							}
						  send(*connect_fd, send_buf, send_bytes, 0);
						}
					}
				}
			  }
			  break;

		}
		break;
	}

	return 0;
}




int is_http_protocol(char *msg_from_client)
{
	/* 只支持HTTP协议，判断方法没写完，先不验证 */

	return 1;

	int index = 0;
	while(msg_from_client[index] != '\0' && msg_from_client[index] != '\n')
	{
		index++;
		printf("%d%c",index - 1,  msg_from_client[index - 1]);
	}
	if(strncmp(msg_from_client + index - 10, "HTTP/", 5) == 0)	/* HTTP Request firt line like this 'GET /index.html HTTP/1.1' , so last 10 byte are HTTP/1.1\r\n*/
	{
		return 1;
	}


	return 0;

}

/*
 * 获取http协议body体里的POST数据
 * req_header    http数据流
 */
char *get_body(char *req_header)
{
	int index = 0;
	char uri_buf[FILE_MAX_SIZE];
	while(req_header[index] != '\0')
	{
		if(( req_header[index] == '\n') && (req_header[index+1] == '\r'))
		{
			index=index+2;
			break;
		}
		else
		{
			index++;
		}
	}

	int base = index;

	while( req_header[index] != '\0')
	{
		index++;
	}
	strncpy(uri_buf, req_header + base + 1, index - base - 1);

	return strdup(uri_buf);
}

/*
 * 根据http流，截取url
 */
char *get_uri(char *req_header, char *uri_buf)
{
	int index = 0;
	char path[RECV_BUFFER_SIZE+1];
	while( (req_header[index] != '/') && (req_header[index] != '\0') )
	{
		index++;
	}
	int base = index;
	while( ((index - base) < URI_SIZE) && (req_header[index] != ' ') && (req_header[index] != '\0') )
	{
		index++;
	}
	if( (index - base) >= URI_SIZE)
	{
		fprintf(stderr, "error: too long of uri request.\n");
		return NULL;
	}
	if((req_header[index - 1] == '/') && (req_header[index] == ' '))
	{
		strcpy(uri_buf, "index.html");
	}
	strncpy(uri_buf, req_header + base + 1, index - base - 1);
	memset(path, '\0', sizeof(path));
	strcpy(path,WEB_ROOT);
	strcat(path,uri_buf);
	strcpy(uri_buf,path);
	return uri_buf;
}

/*
 * 解析http头返回url query ?后面的
 */
char *get_uri_query(char *req_header)
{
	int index = 0;
	if(strchr(req_header,'?')==0)
	{
		return NULL;
	}
	char query_buf[RECV_BUFFER_SIZE];
	memset(query_buf,'\0',sizeof(query_buf));
	while(req_header[index] != '?')
	{
		index++;
	}
	int base = index;
	while( ((index - base) < URI_SIZE) && (req_header[index] != ' ')&& (req_header[index] != '\0') )
	{
		index++;
	}
	if( (index - base) >= URI_SIZE)
	{
		return NULL;
	}
	strncpy(query_buf, req_header + base + 1, index - base - 1);
	return strdup(query_buf);
}

/*
 * 根据url头获取method GET/POST
 */
char *get_uri_method(char *req_header)
{
	int index = 0;
	char uri_buf[RECV_BUFFER_SIZE];
	memset(uri_buf,'\0',sizeof(uri_buf));
	int base = index;
	while( ((index - base) < URI_SIZE) && (req_header[index] != ' ') && (req_header[index] != '\0') )
	{
		index++;
	}
	strncpy(uri_buf, req_header + base, index - base );
	return strdup(uri_buf);
}

/*
 * 解析http协议取出 url头
 */
char *get_uri_file(char *req_header)
{
	int index = 0;
	if(strchr(req_header,'?')==0)
	{
		return req_header;
	}
	char uri_buf[RECV_BUFFER_SIZE];
	memset(uri_buf,'\0',sizeof(uri_buf));
	int base = index;
	while( ((index - base) < URI_SIZE) && (req_header[index] != ' ')&& (req_header[index] != '?') && (req_header[index] != '\0') )
	{
		index++;
	}
	strncpy(uri_buf, req_header + base, index - base );
	return strdup(uri_buf);
}

/*
 * 判断此文件是否存在硬盘上
 */
int get_uri_status(char *uri)
{
	char *uri_file;
	uri_file = get_uri_file(uri);
	//printf("uri_status:%s\n",uri_file);
	if(access(uri_file, F_OK) == -1)
	{
		fprintf(stderr, "File: %s not found.\n", uri);
		return FILE_NOT_FOUND;
	}
	if(access(uri_file, R_OK) == -1)
	{
		fprintf(stderr, "File: %s can not read.\n", uri);
		return FILE_FORBIDEN;
	}
	return FILE_OK;
}

/*
 * 获取url文件扩展名
 */
char *get_url_ext(char *uri)
{
	char *url_file = get_uri_file(uri);
	int len = strlen(url_file);
	int dot = len - 1;
	while( dot >= 0 && url_file[dot] != '.')
	{
		dot--;
	}
	if(dot ==  0)		/* if the uri begain with a dot and the dot is the last one, then it is a bad uri request,so return NULL  */
	{
		return NULL;
	}
	if(dot < 0)			/* the uri is '/',so default type text/html returns */
	{
		return "text/html";
	}
	dot++;
	char *type_off = url_file + dot;
	return strdup(type_off);
}

/*
 * 根据文件类型返回content-type头
 */
char *get_mime_type(char *uri)
{
	char *type_off = get_url_ext(uri);
	if(!strcmp(type_off, "html") || !strcmp(type_off, "HTML"))
	{
		return "text/html";
	}
	if(!strcmp(type_off, "jpeg") || !strcmp(type_off, "JPEG"))
	{
		return "image/jpeg";
	}
	if(!strcmp(type_off, "htm") || !strcmp(type_off, "HTM"))
	{
		return "text/html";
	}
	if(!strcmp(type_off, "css") || !strcmp(type_off, "CSS"))
	{
		return "text/css";
	}
	if(!strcmp(type_off, "png") || !strcmp(type_off, "PNG"))
	{
		return "image/png";
	}
	if(!strcmp(type_off, "jpg") || !strcmp(type_off, "JPG"))
	{
		return "image/jpeg";
	}
	if(!strcmp(type_off, "gif") || !strcmp(type_off, "GIF"))
	{
		return "image/gif";
	}
	if(!strcmp(type_off, "txt") || !strcmp(type_off, "TXT"))
	{
		return "text/plain";
	}
	if(!strcmp(type_off, "php") || !strcmp(type_off, "PHP"))
	{
		return "text/html";
	}
	if(!strcmp(type_off, "js") || !strcmp(type_off, "JS"))
	{
		return "text/javascript";
	}
	return NULL;
}

/*
 * 获取php-cgi执行的字符数，给file_buf赋值
 */
int get_php_cgi(char *uri, char *file_buf,char *recv_buf)
{
	int num;
	num = fork_php_cgi(uri,file_buf,recv_buf);
	return num;
}
/*
 * 通过管道与php-cgi通信，以后单独抽出个文件，做成插件
 * 以后会支持fastcgi scgi 努力
 */
int fork_php_cgi(char *uri, char *file_buf,char *recv_buf)
{
	FILE *fp;
	char cgi_buf[SEND_BUFFER_SIZE];
	char script_filename[URI_SIZE]="SCRIPT_FILENAME=";
	char query_string[URI_SIZE] = "QUERY_STRING=";
	char query_method[URI_SIZE] = "REQUEST_METHOD=";
	char query_content_length[URI_SIZE] = "CONTENT_LENGTH=";
	char post_len[10];
	char *http_post_data;
	char *uri_file = get_uri_file(uri);//文件名
	char *uri_query = get_uri_query(uri);//参数
	char *uri_method = get_uri_method(recv_buf);// GET 或者 POST
	int len;

	int fd1[2];
	int fd2[2];
	pid_t pid;
	char line[RECV_BUFFER_SIZE];
	char sout[SEND_BUFFER_SIZE];

	if ( (pipe(fd1) < 0) || (pipe(fd2) < 0) )
	{
		exit(-2);
	}
	if ( (pid = fork()) < 0 )
	{
		exit(-3);
	}
	else  if (pid == 0)     // CHILD PROCESS
	{
		close(fd1[1]);
		close(fd2[0]);
		if (fd1[0] != STDIN_FILENO)
		{
			if (dup2(fd1[0], STDIN_FILENO) != STDIN_FILENO)
			{
				exit(-4);
			}
			close(fd1[0]);
		}

		if (fd2[1] != STDOUT_FILENO)
		{
			if (dup2(fd2[1], STDOUT_FILENO) != STDOUT_FILENO)
			{
				exit(-5);
			}
			close(fd2[1]);
		}

		//post
		if((!strcmp(uri_method,"POST")) ||(!strcmp(uri_method,"post")))
		{
			http_post_data = get_body(recv_buf);
			len = strlen(http_post_data);
			sprintf(post_len,"%d",len);
			strcat(query_content_length,post_len);
			putenv(query_content_length);
		}
		if(uri_query != NULL)
		{
			strcat(query_string,uri_query);
		}
		memset(cgi_buf,'\0',sizeof(cgi_buf));
		memset(line,'\0',sizeof(line));

		strcat(script_filename,uri_file);
		strcat(query_method,uri_method);
		putenv(script_filename);
		putenv(query_string);
		putenv(query_method);
		putenv("GATEWAY_INTERFACE=CGI/1.1");
		putenv("REDIRECT_STATUS=true");
		putenv("SERVER_PROTOCOL=HTTP/1.1");
		putenv("REMOTE_HOST=127.0.0.1");
		putenv("CONTENT_TYPE=application/x-www-form-urlencoded");
		fp = popen("php-cgi","w");
		fprintf(fp,"%s\n",http_post_data);
		fflush(fp);
		pclose(fp);
		exit(0);

	}
	else        // PARENT PROCESS
	{
		int rv;
		int total_read_bytes=0;
		int index;
		char *powerd = "X-Powered-By:";
		char *content_type = "Content-type:";
		close(fd1[0]);
		close(fd2[1]);

		while((rv=read(fd2[0],line,1024))>0)
		{

			memcpy(sout+total_read_bytes,line,rv);
			total_read_bytes+=rv;
		}
		//替换无效输出
		if(strstr(sout,powerd)!=0)
		{
			while(sout[index]!='\n')
			{
				index++;
			}
		}
		index++;
		if(strstr(sout+index,content_type)!=0)
		{
			while(sout[index]!='\n')
			{
				index++;
			}
		}
		index+=2;//去掉\r\n

		strcpy(file_buf,sout+index);
		return strlen(file_buf);
	}
	return 0;

}
/*
 * 静态文件从硬盘获取返回字节流
 * 动态文件调用管道执行
 */
int get_file_disk(char *uri, char *file_buf,char *recv_buf)
{
	int read_count = 0;
	int fd;
	char *uri_file;
	uri_file = get_uri_file(uri);
	fd = open(uri_file, O_RDONLY);
	//php-cgi
	char *uri_ext = get_url_ext(uri);
	if(!strcmp(uri_ext, "php") || !strcmp(uri_ext, "PHP"))
	{
		read_count = get_php_cgi(uri,file_buf,recv_buf);
		return read_count;
	}
	if(fd == -1)
	{
		perror("open() in get_file_disk http_session.c");
		return -1;
	}
	unsigned long st_size;
	struct stat st;
	if(fstat(fd, &st) == -1)
	{
		perror("stat() in get_file_disk http_session.c");
		return -1;
	}
	st_size = st.st_size;
	if(st_size > FILE_MAX_SIZE)
	{
		fprintf(stderr, "the file %s is too large.\n", uri);
		return -1;
	}
	if((read_count = read(fd, file_buf, FILE_MAX_SIZE)) == -1)
	{
		perror("read() in get_file_disk http_session.c");
		return -1;
	}
	//printf("file %s size : %lu , read %d\n", uri_file, st_size, read_count);
	return read_count;
}

/*
 * 错误处理，目前只有404
 */
int set_error_information(char *send_buf, int errorno)
{
	register int index = 0;
	register int len = 0;
	char *str = NULL;
	switch(errorno)
	{

		case FILE_NOT_FOUND:
			//printf("In set_error_information FILE_NOT_FOUND case\n");
			str = "HTTP/1.1 404 File404 Not Found\r\n";
			len = strlen(str);
			memcpy(send_buf + index, str, len);
			index += len;

			len = strlen(SERVER);
			memcpy(send_buf + index, SERVER, len);
			index += len;

			memcpy(send_buf + index, "\r\nDate:", 7);			
			index += 7;
			
			char time_buf[TIME_BUFFER_SIZE];
			memset(time_buf, '\0', sizeof(time_buf));
			get_time_str(time_buf);
			len = strlen(time_buf);
			memcpy(send_buf + index, time_buf, len);
			index += len;

			str = "\r\nContent-Type:text/html\r\nContent-Length:";
			len = strlen(str);
			memcpy(send_buf + index, str, len);
			index += len;
			
			str = "\r\n\r\n<html><head></head><body>404 File not found<br/>Please check your url,and try it again!</body></html>";
			len = strlen(str);
			int htmllen = len;
			char num_len[5];
			memset(num_len, '\0', sizeof(num_len));
			sprintf(num_len, "%d", len);

			len = strlen(num_len);
			memcpy(send + index, num_len, len);
			index += len;

			memcpy(send_buf + index, str, htmllen);
			index += htmllen;
			break;
		

		default:
			break;
		
	}
	return index;
}

/*
 * 返回组装好的字节流
 */
int reply_normal_information(char *send_buf, char *file_buf, int file_size,  char *mime_type)
{

	char *str =  "HTTP/1.1 200 OK\r\n";
	register int index = strlen(str);
	int len;
	char time_buf[TIME_BUFFER_SIZE];

	memcpy(send_buf, str, index);
	memset(time_buf, '\0', sizeof(time_buf));
	len = strlen(SERVER);
	memcpy(send_buf + index, SERVER, len);
	index += len;

	memcpy(send_buf + index, "\r\nDate:", 7);
	index += 7;
	str = get_time_str(time_buf);
	len = strlen(time_buf);
	memcpy(send_buf + index, time_buf, len);
	index += len;

	memcpy(send_buf + index, "Content-Type:", 13);
	index += 13;
	len = strlen(mime_type);
	memcpy(send_buf + index, mime_type, len);
	index += strlen(mime_type);

	memcpy(send_buf + index, "\r\nContent-Length:", 17);
	index += 17;
	char num_len[8];
	memset(num_len, '\0', sizeof(num_len));
	sprintf(num_len, "%d", file_size);
	len = strlen(num_len);
	memcpy(send_buf + index, num_len, len);
	index += len;
	memcpy(send_buf + index, "\r\n\r\n", 4);
	index += 4;

	memcpy(send_buf + index, file_buf, file_size);

	//printf("%s",send_buf);

	//strcat(send_buf,file_buf);

	index += file_size;
	return index;
	
}
