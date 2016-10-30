#pragma once
//#include "stdafx.h"
#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib,"ws2_32")
class Tcp
{
public:
	Tcp(void);
	~Tcp(void);
	bool connect(char* IPorDNS, int port);
	DWORD resolveIP(char *hostName);
	void disconnect();
	int send(char* buf,int len);
	int recv(char* buf,int len);
	void setRecvTimeOut(int millsecond);
private:
	SOCKET s;
};
