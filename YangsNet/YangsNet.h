// YangsNet.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������
// CYangsNetApp:
// �йش����ʵ�֣������ YangsNet.cpp
//
#include <afxinet.h>
class CYangsNetApp : public CWinApp
{
public:
	CYangsNetApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CYangsNetApp theApp;