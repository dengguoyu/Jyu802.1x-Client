#include "stdafx.h"
#include "Tcp.h"

Tcp::Tcp(void)
{
	s=NULL;
}

Tcp::~Tcp(void)
{
}
void Tcp::setRecvTimeOut(int millsecond)
{
	setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char *)&millsecond,sizeof(int));
}
DWORD Tcp::resolveIP(char *hostName)
{
	hostent *hent;
	char **addresslist;
	DWORD result = 0;

	hent = gethostbyname(hostName);
	if(hent)
	{
		addresslist = hent->h_addr_list;

		if (*addresslist) 
		{
			result = *((DWORD *)(*addresslist));
		}
	}
	if(result == 0)
	{
		DWORD result = inet_addr(hostName);
	}
	return result;
}
bool Tcp::connect(char* IPorDNS, int port) 
{
	DWORD ip = resolveIP(IPorDNS);

	bool ret = false;

	s = socket(AF_INET, SOCK_STREAM, 0);

	if(s == INVALID_SOCKET)
		return false;

	sockaddr_in sin;



	sin.sin_addr.s_addr = ip;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	int error = -1;
	int len = sizeof(int);
	timeval tm;
	fd_set set;
	unsigned long ul = 1;
	ioctlsocket(s, FIONBIO, &ul); //设置为非阻塞模式
	if(::connect(s, (sockaddr *)&sin, sizeof(sin)) == -1)
	{
		tm.tv_sec  = 7;
		tm.tv_usec = 0;
		FD_ZERO(&set);
		FD_SET(s, &set);
		if( select(s+1, NULL, &set, NULL, &tm) > 0)
		{
			getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, /*(socklen_t *)*/&len);
			if(error == 0) 
				ret = true;
			else 
				ret = false;
		} 
		else 
			ret = false;
	}else
	{
		ret=true;
	}
	int timeout=2000;
	//setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(const char *)&timeout,sizeof(int));
	//setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof(int));
	ul=0;
	ioctlsocket(s, FIONBIO, &ul); //设置为阻塞模式
	return ret;
}

void Tcp::disconnect()
{
	closesocket(this->s);
}
int Tcp::recv(char* buf,int len)
{
	return ::recv(s,buf,len,0);
}
int Tcp::send(char* buf,int len )
{
	return ::send(this->s,buf,len,0);
}
