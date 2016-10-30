// YangsNetDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "YangsNet.h"
#include "YangsNetDlg.h"
#define HAVE_REMOTE
#include <pcap.h>
#include "md5.h"
#include <NtDDNdis.h>
#include <Packet32.h>
#include "ping.h"
#include <afxsock.h>
#pragma comment(lib,"wpcap")
#pragma comment(lib,"packet")
char send163[]="GET / HTTP/1.1\r\nHost: 163.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\nConnection: keep-alive\r\n\r\n";
u_char  mac8021x[6]={0x01,0x80,0xc2,0x00,0x00,0x03};/*此地址为专用地址*/
u_char dataStart1[]={0x01,  0x01,  0x00,  0x00,  0x00,  0x00,  0x2F,  0xFC,  0x02,  0x06,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00};
u_char dataStart2[]={0x01,  0x01,  0x00,  0x00,  0xFF,  0xFF,  0x37,  0x77,  0x7F,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xF5,  0x71,  0x00,  0x00,  0x13,  0x11,  0x38,  0x30,  0x32,  0x31,  0x78,  0x2E,  0x65,  0x78,  0x65,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x02,  0x32,  0x00,  0x00,  0x00,  0x00,  0x00,  0x13,  0x11,  0x00,  0x28,  0x1A,  0x28,  0x00,  0x00,  0x13,  0x11,  0x17,  0x22,  0x92,  0x68,  0x64,  0x66,  0x92,  0x94,  0x62,  0x66,  0x91,  0x93,  0x95,  0x62,  0x93,  0x93,  0x91,  0x94,  0x64,  0x61,  0x64,  0x64,  0x65,  0x66,  0x68,  0x94,  0x98,  0xA7,  0x61,  0x67,  0x65,  0x67,  0x9C,  0x6B,  0x00,  0x00,  0x13,  0x11,  0x18,  0x06,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00};
u_char dataRespon34[]={0x01,  0x00,  0x00,  0x17,  0x02,  0x02,  0x00,  0x17,  0x01};
u_char dataRespon34_2[]={  0x00,  0x44,  0x61,  0x00,  0x00,  0xC0,  0xA8,  0x10,  0xFE,  0xFF,  0xFF,  0x37,  0x77,  0x7F,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xF5,  0x71,  0x00,  0x00,  0x13,  0x11,  0x38,  0x30,  0x32,  0x31,  0x78,  0x2E,  0x65,  0x78,  0x65,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x02,  0x32,  0x00,  0x00,  0x00,  0x00,  0x00,  0x13,  0x11,  0x00,  0x28,  0x1A,  0x28,  0x00,  0x00,  0x13,  0x11,  0x17,  0x22,  0x92,  0x68,  0x64,  0x66,  0x92,  0x94,  0x62,  0x66,  0x91,  0x93,  0x95,  0x62,  0x93,  0x93,  0x91,  0x94,  0x64,  0x61,  0x64,  0x64,  0x65,  0x66,  0x68,  0x94,  0x98,  0xA7,  0x61,  0x67,  0x65,  0x67,  0x9C,  0x6B,  0x00,  0x00,  0x13,  0x11,  0x18,  0x06,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00};
u_char dataMD55[]={0x01,  0x00,  0x00,  0x28,  0x02,  0x02,  0x00,  0x28,  0x04,  0x10,  0xAD,  0x5C,  0x59,  0x42,  0x7A,  0x60,  0x15,  0x1A,  0x72,  0xDA,  0x13,  0x4B,  0x9A,  0x78,  0x4E,  0xA6 };
u_char dataMD552[]={  0x00,  0x44,  0x61,  0x02,  0x00,  0xC0,  0xA8,  0x10,  0xFE,  0xFF,  0xFF,  0x37,  0x77,  0x7F,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xF5,  0x71,  0x00,  0x00,  0x13,  0x11,  0x38,  0x30,  0x32,  0x31,  0x78,  0x2E,  0x65,  0x78,  0x65,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x02,  0x32,  0x00,  0x00,  0x00,  0x00,  0x00,  0x13,  0x11,  0x00,  0x28,  0x1A,  0x28,  0x00,  0x00,  0x13,  0x11,  0x17,  0x22,  0x92,  0x68,  0x64,  0x66,  0x92,  0x94,  0x62,  0x66,  0x91,  0x93,  0x95,  0x62,  0x93,  0x93,  0x91,  0x94,  0x64,  0x61,  0x64,  0x64,  0x65,  0x66,  0x68,  0x94,  0x98,  0xA7,  0x61,  0x67,  0x65,  0x67,  0x9C,  0x6B,  0x00,  0x00,  0x13,  0x11,  0x18,  0x06,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00};
u_char dataRequest1[]={0x01,  0x00,  0x00,  0x05,  0x01,  0xff,  0x00,  0x05,  0x01 };
u_char dataRequestMD5[]={0x01,  0x00,  0x00,  0x1A,  0x01,  0x02,  0x00,  0x1A,  0x04,  0x10,  0x45,  0x33,  0x86,  0x79,  0xD2,  0x26,  0xA3,  0xD9,  0xD2,  0x26,  0xA3,  0xD9,  0x00,  0x00,  0x00,  0x00,  0x10,  0x82};
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CYangsNetDlg 对话框




CYangsNetDlg::CYangsNetDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CYangsNetDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CYangsNetDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_Combo1);
	DDX_Control(pDX, IDC_CHECK1, m_Check1);
	DDX_Control(pDX, IDOK, m_okBtn);
}

BEGIN_MESSAGE_MAP(CYangsNetDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDOK, &CYangsNetDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CYangsNetDlg::OnBnClickedCancel)
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_BUTTON2, &CYangsNetDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CYangsNetDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CYangsNetDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON1, &CYangsNetDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON5, &CYangsNetDlg::OnBnClickedButton5)
END_MESSAGE_MAP()


// CYangsNetDlg 消息处理程序

BOOL CYangsNetDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	if (!LoadLibrary("wpcap")||!LoadLibrary("packet"))
	{
		AfxMessageBox("您的电脑尚未安装winpcap组件,无法使用洋哥拨号软件!\r\n请下载winpcap");
		CDialog::OnCancel();
	}
	LastBoHaoStat=0;
	memset(AppPath,0,MAX_PATH);
	GetModuleFileName(GetModuleHandle(NULL),AppPath,MAX_PATH);
	memcpy(AppPath+strlen(AppPath)-4,".ini",4);
	char ID[MAX_PATH]={0};
	char Pass[MAX_PATH]={0};
	GetPrivateProfileString("setting","ID",0,ID,MAX_PATH,AppPath);
	GetPrivateProfileString("setting","Pass",0,Pass,MAX_PATH,AppPath);
	if (strlen(ID)>0)
	{
		SetDlgItemText(IDC_UserName,ID);
		CheckRadioButton(IDC_CHECK1,IDC_CHECK1,IDC_CHECK1);
	}
	if (strlen(Pass)>0)SetDlgItemText(IDC_PassWord,Pass);
	ExtendDiaog(FALSE);
	BeginWork();
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}
void CYangsNetDlg::ExtendDiaog(BOOL bShow)
{
	static CRect m_DlgRectLarge(0, 0, 0, 0);
	static CRect m_DlgRectSmall(0, 0, 0, 0);
	static CRect m_GroupRectLarge(0, 0, 0, 0);
	static CRect m_GroupRectSmall(0, 0, 0, 0);
	AfxSocketInit();
	if ( m_DlgRectLarge.IsRectNull() ) {
		GetWindowRect(&m_DlgRectLarge);
		m_DlgRectSmall = m_DlgRectLarge;
		m_DlgRectSmall.bottom -= 140;

		::GetWindowRect(GetSafeHwnd(), &m_GroupRectLarge);
		m_GroupRectSmall = m_GroupRectLarge;
		m_GroupRectSmall.bottom -= 140;
	}
	if ( bShow ) {
		SetWindowPos(NULL, 0, 0, m_DlgRectLarge.Width(), m_DlgRectLarge.Height(), SWP_NOZORDER | SWP_NOMOVE);
		::SetWindowPos(GetSafeHwnd(), NULL, 0, 0, m_GroupRectLarge.Width(), m_GroupRectLarge.Height(), SWP_NOZORDER | SWP_NOMOVE);
	}else{
		SetWindowPos(NULL, 0, 0, m_DlgRectSmall.Width(), m_DlgRectSmall.Height(), SWP_NOZORDER | SWP_NOMOVE);
		::SetWindowPos(GetSafeHwnd(), NULL, 0, 0, m_GroupRectSmall.Width(), m_GroupRectSmall.Height(), SWP_NOZORDER | SWP_NOMOVE);
	}
}
// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。
bool CYangsNetDlg::IsWrongPass(char* user)
{
	FILE* fp;
	fopen_s(&fp,"WrongPass.txt","rb");
	if (!fp)return false;
	fseek(fp,0,SEEK_END);
	int flen=ftell(fp);
	fseek(fp,0,SEEK_SET);
	char* fbuff=new char[flen+1];
	fbuff[flen]=0;
	fread(fbuff,1,flen,fp);
	fclose(fp);
	char* res=strstr(fbuff,user);
	if (res>0)
	{
		delete[] fbuff;
		return true;
	}
	else
	{
		delete[] fbuff;
		return false;
	}
}
void __stdcall CYangsNetDlg::WatchNet()
{
	return;
	char* sendGet="GET / HTTP/1.1\r\nHost: qq.com\r\n\r\n";
	char* recvBuf=new char[1024*2];
	while(1)
	{
		OnBnClickedButton5();
		Sleep(3000);
		OnBnClickedOk();
 		Tcp tcp;
		if(!tcp.connect("qq.com",80))continue;
		tcp.setRecvTimeOut(1000);
asd:
		tcp.send(sendGet,strlen(sendGet));
		ZeroMemory(recvBuf,1024*2);
		tcp.recv(recvBuf,1024*2);
		recvBuf[1024*2-1]=0;
		if (strstr(recvBuf,"http://210.38.163.138"))
		{
			tcp.disconnect();
			continue;
		}
		Sleep(1000);
		goto asd;
	}
}
void CYangsNetDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CYangsNetDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CYangsNetDlg::OnBnClickedOk()
{
	//GetDlgItem(IDOK)->EnableWindow(false);
	DWORD pFun=0;
	__asm
	{
		mov pFun,offset CYangsNetDlg::WorkThreadProc;
	}
	CloseHandle(CreateThread(0,0,(LPTHREAD_START_ROUTINE)pFun,this,0,0));

	// TODO: 在此添加控件通知处理程序代码
	//OnOK();
}

void CYangsNetDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	char buff[1500]={0};
	char errBuf[PCAP_ERRBUF_SIZE]={0};
	CComboBox* pCom=((CComboBox*)GetDlgItem(IDC_COMBO1));
	CString s=CString((char*)pCom->GetItemData(pCom->GetCurSel()));
	pcap_t* ph=pcap_open_live(s.GetString(),1500,PCAP_OPENFLAG_PROMISCUOUS,1,errBuf);
	memcpy(buff,mac8021x,6);
	USHORT* type802=(USHORT*)(buff+12);
	*type802=htons(Protocol8021X);
	EAPHEADER* peap=(EAPHEADER*)(buff+14);
	peap->PackType=2;
	peap->Version=1;
	GetMacAddr((char*)s.GetString(),(UCHAR*)(buff+6),6);
	pcap_sendpacket(ph,(const unsigned char*)buff,sizeof(ETHERHEADER)+sizeof(EAPHEADER));
	pcap_close(ph);
	SetDlgItemText(IDC_STATIC,"发送注销信息成功!");
}

void CYangsNetDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	for (int i=0;i<m_Combo1.GetCount();i++)
	{
		delete[] (char*)(m_Combo1.GetItemData(i));
	}
	_CrtDumpMemoryLeaks();
	CDialog::OnClose();
	ExitProcess(0);
}

void CYangsNetDlg::BeginWork()
{
	pcap_if_t* pDevices=0;
	pcap_if_t* pt=0;
	char errBuff[PCAP_ERRBUF_SIZE]={0};
	pcap_findalldevs(&pDevices,errBuff);
	int i=0;
	for (pt=pDevices;pt;pt=pt->next)
	{
		m_Combo1.InsertString(i,pt->description);
		char* idata=new char[strlen(pt->name)+1];
		strcpy_s(idata,strlen(pt->name)+1,pt->name);
		m_Combo1.SetItemData(i,(DWORD)idata);
		i++;
	}
	pcap_freealldevs(pDevices);
	if (i<1)
	{
		AfxMessageBox("在您的机器上未发现任何网卡,请确保您确实想上网!!!!!!!!");
		CDialog::OnCancel();
	}else	m_Combo1.SetCurSel(0);
	DWORD rax;
	__asm mov rax,offset CYangsNetDlg::WatchNet;
	CloseHandle(CreateThread(0,0,(LPTHREAD_START_ROUTINE)rax,this,0,0));
}

void __stdcall CYangsNetDlg::WorkThreadProc()
{
	if (GetDlgItem(IDC_UserName)->GetWindowTextLength()<=0
		||
		GetDlgItem(IDC_PassWord)->GetWindowTextLength()<=0)
	{
		SetDlgItemText(IDC_STATIC,"用户名或密码没输入");
		GetDlgItem(IDOK)->EnableWindow(true);
		return;
	}
	pcap_t* ph=0;
	char* errBuf=new char[PCAP_ERRBUF_SIZE];
	CString DeviceName=CString((char*)m_Combo1.GetItemData(m_Combo1.GetCurSel()));
	CString UserName;
	CString UserPass;
	GetDlgItemText(IDC_UserName,UserName);
	GetDlgItemText(IDC_PassWord,UserPass);
	ph=pcap_open(DeviceName.GetString(),1500,PCAP_OPENFLAG_PROMISCUOUS,1,0,errBuf);
 	if (!ph)
 	{
 		DeviceName.Format("打开设备失败!:\r\n%s",errBuf);
		SetDlgItemText(IDC_STATIC,DeviceName);
		m_okBtn.EnableWindow(TRUE);
		delete[] errBuf;
		pcap_close(ph);
		return ;
 	}
	delete[] errBuf;
	//u_char* pBuff=new u_char[1500];
	u_char pBuff[1500];
	memset(pBuff,0,1500);
	ETHERHEADER* phEther=(ETHERHEADER*)pBuff;
	EAPHEADER* phEap=(EAPHEADER*)(pBuff+sizeof(ETHERHEADER));
	if(!GetMacAddr((char*)DeviceName.GetString(),phEther->srcmac,6))
	{
		DeviceName.Format("获取网卡mac地址失败!!");
		SetDlgItemText(IDC_STATIC,DeviceName);
/*		delete[] pBuff;*/
		m_okBtn.EnableWindow(TRUE);
		pcap_close(ph);
		return ;
	}
	//OnBnClickedCancel();
	memcpy(phEther->dstmac,mac8021x,6);
	phEther->utype=htons(Protocol8021X);
	//ether ok
	memcpy(pBuff+sizeof(ETHERHEADER),dataStart1,sizeof(dataStart1));
	pcap_sendpacket(ph,pBuff,sizeof(ETHERHEADER)+sizeof(dataStart1));
	//memcpy(pBuff+sizeof(ETHERHEADER),dataStart2,sizeof(dataStart2));
	//pcap_sendpacket(ph,pBuff,sizeof(ETHERHEADER)+sizeof(dataStart2));
	int ires=0;
	pcap_pkthdr* pkd=0;
	//u_char* pRecvBuff=new u_char[1500];
	u_char pRecvBuff[1500];
	u_char* ptempbuff=0;
	memset(pRecvBuff,0,1500);
	ETHERHEADER* phEther2=(ETHERHEADER*)pRecvBuff;
	EAPHEADER* phEap2=(EAPHEADER*)(pRecvBuff+sizeof(ETHERHEADER));
	//发完2个start该等request了
	SetDlgItemText(IDC_STATIC,"正在拨号...(1/5)");
	int tickcount=GetTickCount();
	while(ires=pcap_next_ex(ph,&pkd,(const unsigned char**)&ptempbuff)>=0)
	{
		if ((GetTickCount()-tickcount)>2*1000)
		{
			SetDlgItemText(IDC_STATIC,"连接超时(2秒无响应)");
			LastBoHaoStat=-1;
// 			delete[] pBuff;
// 			delete[] pRecvBuff;
			m_okBtn.EnableWindow(TRUE);
			pcap_close(ph);
			return ;
		}
		if (ires=0)continue;
		if ((pkd->caplen)>=(sizeof(ETHERHEADER)+sizeof(dataRequest1))&&(!(pkd->caplen>1500)))
		{
			memcpy(pRecvBuff,ptempbuff,pkd->caplen);
			if (!memcmp(pRecvBuff+sizeof(ETHERHEADER),dataRequest1,5) && 
				!memcmp(pRecvBuff+sizeof(ETHERHEADER)+6,dataRequest1+6,sizeof(dataRequest1)-6))
			{
				SetDlgItemText(IDC_STATIC,"正在拨号...(2/5)");
				break;
			}
		}else
		{
			continue;
		}
	}
	memcpy(phEther->dstmac,phEther2->srcmac,6);
	memcpy(pBuff+sizeof(ETHERHEADER),dataRespon34,sizeof(dataRespon34));
	memcpy(pBuff+sizeof(ETHERHEADER)+sizeof(dataRespon34),UserName.GetString(),UserName.GetLength());
	memcpy(pBuff+sizeof(ETHERHEADER)+sizeof(dataRespon34)+UserName.GetLength(),dataRespon34_2,sizeof(dataRespon34_2));
	phEap->ExtData.Identifer=phEap2->ExtData.Identifer;
	pcap_sendpacket(ph,pBuff,sizeof(ETHERHEADER)+sizeof(dataRespon34)+sizeof(dataRespon34_2)+UserName.GetLength());
//	tickcount=GetTickCount();
//	while(ires=pcap_next_ex(ph,&pkd,(const unsigned char**)&ptempbuff)>=0)
//	{
//		if ((GetTickCount()-tickcount)>3*1000)
//		{
//			SetDlgItemText(IDC_STATIC,"连接超时(2秒无响应)");
//			LastBoHaoStat=-1;
//// 			delete[] pBuff;
//// 			delete[] pRecvBuff;
//			m_okBtn.EnableWindow(TRUE);
//			pcap_close(ph);
//			return ;
//		}
//		if (ires=0)continue;
//
//		if ((pkd->caplen)>=(sizeof(ETHERHEADER)+sizeof(dataRequest1))&&(!(pkd->caplen>1500)))
//		{
//			memcpy(pRecvBuff,ptempbuff,pkd->caplen);
//			if (!memcmp(pRecvBuff+sizeof(ETHERHEADER),dataRequest1,5) && 
//				!memcmp(pRecvBuff+sizeof(ETHERHEADER)+6,dataRequest1+6,sizeof(dataRequest1)-6))
//			{
//				SetDlgItemText(IDC_STATIC,"正在拨号...(3/5)");
//				break;
//			}
//		}
//		else
//		{
//			continue;
//		}
//	}
//	memcpy(pBuff+sizeof(ETHERHEADER),dataRespon34,sizeof(dataRespon34));
//	GetDlgItemText(IDC_UserName,UserName);
//	memcpy(pBuff+sizeof(ETHERHEADER)+sizeof(dataRespon34),UserName.GetString(),UserName.GetLength());
//	memcpy(pBuff+sizeof(ETHERHEADER)+sizeof(dataRespon34)+UserName.GetLength(),dataRespon34_2,sizeof(dataRespon34_2));
//	phEap->ExtData.Identifer=phEap2->ExtData.Identifer;
//	pcap_sendpacket(ph,pBuff,sizeof(ETHERHEADER)+sizeof(dataRespon34)+sizeof(dataRespon34_2)+UserName.GetLength());
	tickcount=GetTickCount();
	while(ires=pcap_next_ex(ph,&pkd,(const unsigned char**)&ptempbuff)>=0)
	{
		if ((GetTickCount()-tickcount)>3*1000)
		{
			SetDlgItemText(IDC_STATIC,"连接超时(2秒无响应)");
			LastBoHaoStat=-1;
// 			delete[] pBuff;
// 			delete[] pRecvBuff;
			m_okBtn.EnableWindow(TRUE);
			pcap_close(ph);
			return ;
		}
		if (ires=0)continue;
		if ((pkd->caplen)>=(sizeof(ETHERHEADER)+sizeof(dataRequestMD5))&&(!(pkd->caplen>1500)))
		{
			memcpy(pRecvBuff,ptempbuff,pkd->caplen);
			if (!memcmp(pRecvBuff+sizeof(ETHERHEADER),dataRequestMD5,5) &&
				!memcmp(pRecvBuff+sizeof(ETHERHEADER)+6,dataRequestMD5+6,4))
			{
				SetDlgItemText(IDC_STATIC,"正在拨号...(4/5)");
				break;
			}
		}
		else
		{
			continue;
		}
	}
	u_char md5buf[128]={0};
	memset(pBuff+sizeof(ETHERHEADER),0,1500-sizeof(ETHERHEADER));
	md5buf[0]=phEap2->ExtData.Identifer;
	memcpy(md5buf+1,UserPass.GetString(),UserName.GetLength());
	memcpy(md5buf+1+UserPass.GetLength(),phEap2->ExtData.Data.Md5Data.Value,16);
	memcpy(pBuff+sizeof(ETHERHEADER),dataMD55,sizeof(dataMD55));
	memcpy(pBuff+sizeof(ETHERHEADER)+sizeof(dataMD55),UserName.GetString(),UserName.GetLength());
	memcpy(pBuff+sizeof(ETHERHEADER)+sizeof(dataMD55)+UserName.GetLength(),dataMD552,sizeof(dataMD552));
	phEap->ExtData.Identifer=phEap2->ExtData.Identifer;
	MD5_CTX mdfive;
	mdfive.MD5Update(md5buf,UserPass.GetLength()+17);
	mdfive.MD5Final(pBuff+sizeof(ETHERHEADER)+10);
	pcap_sendpacket(ph,pBuff,sizeof(ETHERHEADER)+sizeof(dataMD55)+sizeof(dataMD552)+UserName.GetLength());
	tickcount=GetTickCount();
	SetDlgItemText(IDC_STATIC,"正在拨号...(5/5)");
	while(ires=pcap_next_ex(ph,&pkd,(const unsigned char**)&ptempbuff)>=0)
	{
		if ((GetTickCount()-tickcount)>3*1000)
		{
			SetDlgItemText(IDC_STATIC,"连接超时(2秒无响应)");
			LastBoHaoStat=-1;
// 			delete[] pBuff;
// 			delete[] pRecvBuff;
			m_okBtn.EnableWindow(TRUE);
			pcap_close(ph);
			return ;
		}
		if (ires=0)continue;
		if ((pkd->caplen)>=(sizeof(ETHERHEADER)+8)&&(!(pkd->caplen>1500)))
		{
			memcpy(pRecvBuff,ptempbuff,pkd->caplen);
			if (phEther2->utype==htons(Protocol8021X)&&
				phEap2->Version==0x1 &&
				phEap2->PackType==0 &&
				phEap2->Length!=htons(40))
			{

				if (phEap2->ExtData.Code!=Success)
				{
					SetDlgItemText(IDC_STATIC,"账号或密码错误!...(5/5)");
					LastBoHaoStat=0;
					Sleep(3000);
					FILE* ffp;
					ffp=fopen("WrongPass.txt","ab");
					fwrite(UserName.GetString(),1,UserName.GetLength(),ffp);
					fwrite(",",1,1,ffp);
					fwrite(UserPass.GetString(),1,UserPass.GetLength(),ffp);
					fwrite("\r\n",1,2,ffp);
					fclose(ffp);
					break;
				}else
				{
					SetDlgItemText(IDC_STATIC,"拨号成功!...(5/5)");
					LastBoHaoStat=1;
					SaveAccount();
					break;
				}
			}
			else
			{
				continue;
			}
		}
	}
// 	delete[] pBuff;
// 	delete[] pRecvBuff;
	pcap_close(ph);
	m_okBtn.EnableWindow(TRUE);
}



BOOL CYangsNetDlg::GetMacAddr( __in char* AdapterName,__out u_char* MacBuf,__in int BufLen )
//获取mac达
{
	if(!AdapterName || !MacBuf || BufLen<6)
		return FALSE;
	LPADAPTER	lpAdapter = 0;
	PPACKET_OID_DATA  OidData;
	BOOLEAN		Status;
	lpAdapter =   PacketOpenAdapter(AdapterName);
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
		return FALSE;
	OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL) 
	{
		PacketCloseAdapter(lpAdapter);
		return FALSE;
	}
	// 
	// Retrieve the adapter MAC querying the NIC driver
	//
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);
	Status = PacketRequest(lpAdapter, FALSE, OidData);
	PacketCloseAdapter(lpAdapter);
	if(Status)
	{
		memcpy(MacBuf,OidData->Data,6);
	}
	free(OidData);
	return Status;
} 

void CYangsNetDlg::SaveAccount()
{
	char str[128];
	if (m_Check1.GetCheck()==1)
	{
		GetDlgItemText(IDC_UserName,str,128);
		WritePrivateProfileString("setting","ID",str,AppPath);
		GetDlgItemText(IDC_PassWord,str,128);
		WritePrivateProfileString("setting","Pass",str,AppPath);
	}
}


void CYangsNetDlg::OnBnClickedButton2()
{
	__asm mov esp,0
	CDialog::OnCancel();
	// TODO: 在此添加控件通知处理程序代码
}

void CYangsNetDlg::OnBnClickedButton3()
{
	ShowWindow(SW_MINIMIZE);
	// TODO: 在此添加控件通知处理程序代码
}

void CYangsNetDlg::OnBnClickedButton4()
{
	static bool bShowSetting=true;
	if (bShowSetting)
	{
		bShowSetting=false;
		ExtendDiaog(!bShowSetting);
	}else
	{
		bShowSetting=true;
		ExtendDiaog(!bShowSetting);
	}
	// TODO: 在此添加控件通知处理程序代码
}

void CYangsNetDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
}

void CYangsNetDlg::OnBnClickedButton5()
{
	while(1)
	{
		FILE* fp;
		fopen_s(&fp,"Success.txt","rb");
		if(!fp)return;
		fseek(fp,0,SEEK_END);
		int flen=ftell(fp);
		fseek(fp,0,SEEK_SET);
		char* fbuff=new char[flen];
		fread(fbuff,1,flen,fp);
		fclose(fp);

		CString s;
		int pos=0;
		FILE* fpp;
		char fppbuf[32]={0};
		fopen_s(&fpp,"pos.txt","rb");
		fread(fppbuf,1,32,fpp);
		fclose(fpp);
		pos=atoi(fppbuf);

		char temp[64]={0};
		if (pos>=flen)pos=0;
		memcpy(temp,fbuff+pos,9);
		SetDlgItemText(IDC_UserName,temp);
		bool iswrong=IsWrongPass(temp);
		pos+=10;
		memset(temp,0,64);
		memcpy(temp,fbuff+pos,8);
		pos+=10;
		FILE* fpwp;
		fopen_s(&fpwp,"pos.txt","wb");
		CString charpos;
		charpos.Format("%d",pos);
		fwrite(charpos.GetString(),1,charpos.GetLength(),fpwp);
		fclose(fpwp);
		SetDlgItemText(IDC_PassWord,temp);
		if (iswrong)
		{continue;
		}else{
			break;
		}
	}
	// TODO: 在此添加控件通知处理程序代码
}
