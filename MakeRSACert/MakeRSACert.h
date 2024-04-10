// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the MAKERSACERT_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// MAKERSACERT_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MAKERSACERT_EXPORTS
#define MAKERSACERT_API __declspec(dllexport)
#else
#define MAKERSACERT_API __declspec(dllimport)
#endif

/*
// This class is exported from the MakeRSACert.dll
class MAKERSACERT_API CMakeRSACert {
public:
	CMakeRSACert(void);
	// TODO: add your methods here.
};

extern MAKERSACERT_API int nMakeRSACert;

MAKERSACERT_API int fnMakeRSACert(void);
*/

MAKERSACERT_API DWORD fnMakeRSACertByP10(IN char* p10Base64Data, OUT char* pCertData, OUT long* lCertLen);