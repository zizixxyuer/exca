// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SKFDOIT_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SKFDOIT_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef SKFDOIT_EXPORTS
#define SKFDOIT_API __declspec(dllexport)
#else
#define SKFDOIT_API __declspec(dllimport)
#endif

/*
// This class is exported from the SKFDoit.dll
class SKFDOIT_API CSKFDoit {
public:
	CSKFDoit(void);
	// TODO: add your methods here.
};

extern SKFDOIT_API int nSKFDoit;

SKFDOIT_API int fnSKFDoit(void);
*/

SKFDOIT_API DWORD fnGenP10SM2BySoft(IN char* pData, OUT char* pP10Base64Data, OUT long* lP10Base64Datalen);

SKFDOIT_API DWORD fnSaveSM2CertBySoft(IN char* certBase64, IN char* pPfxPath, IN char* pPassWord);