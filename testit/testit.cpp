// testit.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <vector>
#include <string>

//CSPDoit.dll
typedef DWORD(*tfnGenP10BySoft)(IN char* pData, IN char* keyBitsLen, OUT char* pP10Base64Data, OUT long* lP10Base64Datalen);
typedef DWORD(*tfnSaveRSACertBySoft)(IN char* certBase64, IN char* pPfxPath, IN char* pPassWord);

//MakeRSACert.dll
typedef DWORD(*tfnMakeRSACertByP10)(IN char* p10Base64Data, OUT char* pCertData, OUT long* lCertLen);

//SKFDOit.dll
typedef DWORD(*tfnGenP10SM2BySoft)(IN char* pData, OUT char* pP10Base64Data, OUT long* lP10Base64Datalen);
typedef DWORD(*tfnSaveSM2CertBySoft)(IN char* certBase64, IN char* pPfxPath, IN char* pPassWord);

//MakeSM2Cert.dll
typedef DWORD(*fnMakeSM2CertByP10)(IN char* p10Base64Data, OUT char* pCertData, OUT long* lCertLen);

int main()
{
	//rsa
	HMODULE hCSPDoit = LoadLibrary(_T("CSPDoit.dll"));
	tfnGenP10BySoft GenP10BySoft = (tfnGenP10BySoft)GetProcAddress(hCSPDoit, "fnGenP10BySoft");
	tfnSaveRSACertBySoft SaveRSACertBySoft = (tfnSaveRSACertBySoft)GetProcAddress(hCSPDoit, "fnSaveRSACertBySoft");

	HMODULE hMakeRSACert = LoadLibrary(_T("MakeRSACert.dll"));
	tfnMakeRSACertByP10 MakeRSACertByP10 = (tfnMakeRSACertByP10)GetProcAddress(hMakeRSACert, "fnMakeRSACertByP10");

	DWORD dwRet = 0;

	//gen rsa p10
	std::vector<char> pP10Base64Data(4096);
	long lP10Base64Len = 4096;
	dwRet = GenP10BySoft("{\"CN\":\"Tom\",\"C\":\"CN\",\"S\":\"beijing\",\"L\":\"HaiDian\",\"O\":\"Test\",\"OU\":\"Test1\"}", "1024", &pP10Base64Data[0], &lP10Base64Len);
	if (0 != dwRet)
	{
		printf("\r\nGenP10BySoft ERR!\r\n");
	}
	printf("\r\nrsa p10:\r\n");
	std::string p10str(&pP10Base64Data[0]);
	printf(p10str.c_str());

	//gen rsa cert
	std::vector<char> pCertData(4096);
	long lCertLen = 4096;
	dwRet = MakeRSACertByP10(&pP10Base64Data[0], &pCertData[0], &lCertLen);
	if (0 != dwRet)
	{
		printf("\r\nMakeRSACertByP10 ERR!\r\n");
	}
	printf("\r\nrsa cert:\r\n");
	std::string rsacertstr(&pCertData[0]);
	printf(rsacertstr.c_str());

	//save rsa pfx
	dwRet = SaveRSACertBySoft((char*)&pCertData[0], (char*)"rsa.pfx", (char*)"123456");
	if (0 != dwRet)
	{
		printf("\r\nSaveRSACertBySoft ERR!\r\n");
	}
	printf("\r\nSaveRSACertBySoft SUCCEED!\r\n");


	//sm2
	HMODULE hSKFDoit = LoadLibrary(_T("SKFDoit.dll"));
	tfnGenP10SM2BySoft GenP10SM2BySoft = (tfnGenP10SM2BySoft)GetProcAddress(hSKFDoit, "fnGenP10SM2BySoft");
	tfnSaveSM2CertBySoft SaveSM2CertBySoft = (tfnSaveSM2CertBySoft)GetProcAddress(hSKFDoit, "fnSaveSM2CertBySoft");

	HMODULE hMakeSM2Cert = LoadLibrary(_T("MakeSM2Cert.dll"));
	fnMakeSM2CertByP10 MakeSM2CertByP10 = (fnMakeSM2CertByP10)GetProcAddress(hMakeSM2Cert, "fnMakeSM2CertByP10");

	//gen sm2 p10
	pP10Base64Data.resize(4096);
	ZeroMemory(&pP10Base64Data[0], 4096);
	lP10Base64Len = 4096;
	dwRet = GenP10SM2BySoft("{\"CN\":\"Tom\",\"C\":\"CN\",\"S\":\"beijing\",\"L\":\"HaiDian\",\"O\":\"Test\",\"OU\":\"Test1\"}", &pP10Base64Data[0], &lP10Base64Len);
	if (0 != dwRet)
	{
		printf("\r\nGenP10SM2BySoft ERR!\r\n");
	}
	printf("\r\nsm2 p10:\r\n");
	std::string sm2p10str(&pP10Base64Data[0]);
	printf(sm2p10str.c_str());

	//gen sm2 cert
	ZeroMemory(&pCertData[0], 4096);
	lCertLen = 4096;
	dwRet = MakeSM2CertByP10(&pP10Base64Data[0], &pCertData[0], &lCertLen);
	if (0 != dwRet)
	{
		printf("\r\nMakeSM2CertByP10 ERR!\r\n");
	}
	printf("\r\nsm2 cert:\r\n");
	std::string sm2certstr(&pCertData[0]);
	printf(sm2certstr.c_str());

	//save sm2 pfx
	dwRet = SaveSM2CertBySoft((char*)&pCertData[0], (char*)"sm2.pfx", (char*)"123456");
	if (0 != dwRet)
	{
		printf("\r\nSaveSM2CertBySoft ERR!\r\n");
	}
	printf("\r\nSaveSM2CertBySoft SUCCEED!\r\n");

	system("PAUSE");

    return 0;
}

