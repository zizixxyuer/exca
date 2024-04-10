// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the MAKESM2CERT_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// MAKESM2CERT_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MAKESM2CERT_EXPORTS
#define MAKESM2CERT_API __declspec(dllexport)
#else
#define MAKESM2CERT_API __declspec(dllimport)
#endif

/*
// This class is exported from the MakeSM2Cert.dll
class MAKESM2CERT_API CMakeSM2Cert {
public:
	CMakeSM2Cert(void);
	// TODO: add your methods here.
};

extern MAKESM2CERT_API int nMakeSM2Cert;

MAKESM2CERT_API int fnMakeSM2Cert(void);
*/

MAKESM2CERT_API DWORD fnMakeSM2CertByP10(IN char* p10Base64Data, OUT char* pCertData, OUT long* lCertLen);