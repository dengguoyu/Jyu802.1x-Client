// YangsNetDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "Tcp.h"

// CYangsNetDlg �Ի���
class CYangsNetDlg : public CDialog
{
private:
	void BeginWork();
	void __stdcall WorkThreadProc();
	BOOL GetMacAddr(__in char* AdapterName,__out u_char* MacBuf,__in int BufLen);
	char  AppPath[MAX_PATH];
	void SaveAccount();
	void CYangsNetDlg::ExtendDiaog(BOOL bShow);
	void __stdcall WatchNet();
	int LastBoHaoStat;
// ����
public:
	CYangsNetDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_YANGSNET_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��
	

// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnClose();
	CComboBox m_Combo1;
	CButton m_Check1;
	CButton m_okBtn;
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedButton1();
	bool IsWrongPass(char* user);
	afx_msg void OnBnClickedButton5();
};
#pragma pack(1)

/*
erthernat header
*/
typedef struct _ETHERHEADER
{
	u_char dstmac[6];
	u_char srcmac[6];
	USHORT utype;
#define Protocol8021X    0x888e/*8021.x��֤Э��*/
}ETHERHEADER;
/*
 *802.1x authentication  48�ֽ�
 */
typedef struct _EAPHEADER
{
    u_char Version;   /*�汾��:2*/
    u_char PackType;  /*����*/
      #define   EAPOL    0x01 /*authentication start*/
      #define   EAP      0x00 /*Eap packet*/
      #define   LOGOFF   0x02 /*logoff*/
    WORD   Length;/*the following extension data length*/
    struct
    {
       u_char Code;/*eap code*/
        #define Req        0x01  /*request flag */
        #define Response   0x02  /*response flag*/
        #define Success    0x03  /*success */
        #define False      0x04  /*ʧ��*/
       u_char Identifer;         /*��Ӧ������ͬ��������������ͬ*/
       WORD   Length;/*length of ExtData*/
       u_char Type;  /*��֤����*/
        #define IDentity  0x01  /*�ʺ���֤*/
        #define MD5Pass   0x04  /*md5��֤*/
      union 
      {
       struct
       {
        u_char ValueSize;/*ֵ�Ĵ�С*/
        u_char Value[36];/*��֤����ethernet֡Ϊ60�ֽ�*/
       }Md5Data;
       u_char IdData[37];
      }Data;
      
    }ExtData;
}EAPHEADER;
#pragma pack()


