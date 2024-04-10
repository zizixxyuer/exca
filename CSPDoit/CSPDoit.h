// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the CSPDOIT_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// CSPDOIT_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef CSPDOIT_EXPORTS
#define CSPDOIT_API __declspec(dllexport)
#else
#define CSPDOIT_API __declspec(dllimport)
#endif

/*
// This class is exported from the CSPDoit.dll
class CSPDOIT_API CCSPDoit {
public:
	CCSPDoit(void);
	// TODO: add your methods here.
};

extern CSPDOIT_API int nCSPDoit;

CSPDOIT_API int fnCSPDoit(void);
*/

CSPDOIT_API DWORD fnGenP10BySoft(IN char* pData, IN char* keyBitsLen, OUT char* pP10Base64Data, OUT long* lP10Base64Datalen);

CSPDOIT_API DWORD fnSaveRSACertBySoft(IN char* certBase64, IN char* pPfxPath, IN char* pPassWord);