#include "stdafx.h"
#include "SKFDoit.h"

#include "rapidjson/memorystream.h"
#include "rapidjson/document.h"

#include <codecvt>
#include <memory>
#include <functional>
#include <vector>
#include <map>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/sm3.h>
#include <openssl/ec.h>
#include <openssl/x509v3.h>

#include "smalg.h"
#include "string_convert.h"

//#define _X509_REQ_V
static const char* kPrivKeyFile_user = "keycert\\private_user.key";
static const char* keycertPath = "keycert\\";

void AddTempPath(char* pOut, const char* pIn)
{
	char szTemp[MAX_PATH] = { 0 };
	GetTempPathA(MAX_PATH, szTemp);
	strcat(szTemp, pIn);
	memcpy(pOut, szTemp, strlen(szTemp));

	return;
}

#define _TEST_commonName_ "test1"
#define _TEST_localityName_ "BeiJing"
#define _TEST_organizationName_ "Company"
#define _TEST_organizationalUnitName_ "Test"
#define _TEST_countryName_ "CN"
#define _TEST_stateOrProvinceName "HaiDian"

static const char* kKeySubjectC = "C";
static const char* kKeySubjectS = "S";
static const char* kKeySubjectL = "L";
static const char* kKeySubjectO = "O";
static const char* kKeySubjectOU = "OU";
static const char* kKeySubjectCN = "CN";

BOOL check_char_ptr(char* p)
{
	if (NULL == p || strlen(p) == 0)
	{
		return FALSE;
	}

	return TRUE;
}

#define CHECK_OPENSSL_BOJECT(obj) do {\
	if (!obj) {\
		return 5;\
	}\
}while(0)

#define SHOULD_OPT_FAILED(ret) do{\
	if (ret == 0) {\
		return 2;\
	}\
}while(0)

#define CHECKAPI_PTR(x)	if (NULL == pskfapi->##x)	\
						{	\
							return 6;	\
						}

#define CHECKRET_CODE(x)	if (SAR_OK != x)	\
						{	\
							return x;	\
						}

using  utf8_cvt = std::codecvt_utf8<wchar_t>;

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509_REQ_ptr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using X509_NAME_ptr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using PKCS12_ptr = std::unique_ptr<PKCS12, decltype(&PKCS12_free)>;

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&RSA_free)>;

using EC_KEY_ptr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using ESDSA_SIG_ptr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

int SavePrivateKey(EVP_PKEY * key, const char* pwd)
{
	BIO_ptr out(BIO_new(BIO_s_file()), BIO_free);
	CHECK_OPENSSL_BOJECT(out);

	const EVP_CIPHER* enc = nullptr;
	if (pwd) {
		enc = EVP_des_ede3_cbc();
	}

	char szkPrivKeyFile_user[MAX_PATH] = { 0 };
	//AddTempPath(szkPrivKeyFile_user, kPrivKeyFile_user);
	strcat(szkPrivKeyFile_user, kPrivKeyFile_user);

	BIO_write_filename(out.get(), (void*)szkPrivKeyFile_user);
	int ret = PEM_write_bio_PKCS8PrivateKey(out.get(), key, enc, nullptr, 0, nullptr, (void*)pwd);
	SHOULD_OPT_FAILED(ret);
	return 0;
}

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return 0;
	sk_X509_EXTENSION_push(sk, ex);

	return 1;
}

SKFDOIT_API DWORD fnGenP10SM2BySoft(
	IN char* pData,
	OUT char* pP10Base64Data,
	OUT long* lP10Base64Datalen
	)
{
	if (!check_char_ptr(pData))
	{
		return 1;
	}

	*lP10Base64Datalen = 0;

	rapidjson::MemoryStream j_data(pData, strlen(pData));
	rapidjson::Document doc_;
	doc_.ParseStream(j_data);
	if (doc_.HasParseError()) {
		return 2;
	}

	std::string str_CN = doc_.HasMember(kKeySubjectCN) && doc_[kKeySubjectCN].IsString() ? doc_[kKeySubjectCN].GetString() : "";
	std::string str_OU = doc_.HasMember(kKeySubjectOU) && doc_[kKeySubjectOU].IsString() ? doc_[kKeySubjectOU].GetString() : "";
	std::string str_O = doc_.HasMember(kKeySubjectO) && doc_[kKeySubjectO].IsString() ? doc_[kKeySubjectO].GetString() : "";
	std::string str_L = doc_.HasMember(kKeySubjectL) && doc_[kKeySubjectL].IsString() ? doc_[kKeySubjectL].GetString() : "";
	std::string str_S = doc_.HasMember(kKeySubjectS) && doc_[kKeySubjectS].IsString() ? doc_[kKeySubjectS].GetString() : "";
	std::string str_C = doc_.HasMember(kKeySubjectC) && doc_[kKeySubjectC].IsString() ? doc_[kKeySubjectC].GetString() : "";
	str_CN = str_CN == "" ? _TEST_commonName_ : str_CN;
	str_OU = str_OU == "" ? _TEST_organizationalUnitName_ : str_OU;
	str_O = str_O == "" ? _TEST_organizationName_ : str_O;
	str_L = str_L == "" ? _TEST_localityName_ : str_L;
	str_S = str_S == "" ? _TEST_stateOrProvinceName : str_S;
	str_C = str_C == "" ? _TEST_countryName_ : str_C;

	X509_NAME_ptr subject(X509_NAME_new(), X509_NAME_free);
	CHECK_OPENSSL_BOJECT(subject);

	auto subjectAddItem = [&subject](int nid, std::string v) -> int {
		if (v.empty()) return 1;  //same as openssl return value
		return X509_NAME_add_entry_by_NID(subject.get(), nid, MBSTRING_UTF8, (unsigned char*)v.c_str(), v.length(), -1, 0);
	};

	subjectAddItem(NID_commonName, str_CN);
	subjectAddItem(NID_countryName, str_C);
	subjectAddItem(NID_localityName, str_L);
	subjectAddItem(NID_organizationName, str_O);
	subjectAddItem(NID_organizationalUnitName, str_OU);
	subjectAddItem(NID_stateOrProvinceName, str_S);

	X509_REQ_ptr x509Req(X509_REQ_new(), X509_REQ_free);
	CHECK_OPENSSL_BOJECT(x509Req);

	X509_REQ_set_version(x509Req.get(), 1);
	X509_REQ_set_subject_name(x509Req.get(), subject.get());

	STACK_OF(X509_EXTENSION) *exts = NULL;
	exts = sk_X509_EXTENSION_new_null();
	add_ext(exts, NID_key_usage, "critical,digitalSignature,keyEncipherment");
	//add_ext(exts, NID_key_usage, "critical,digitalSignature,nonRepudiation");		//only sign
	//add_ext(exts, NID_key_usage, "critical,keyEncipherment,dataEncipherment");	//only keyenc

	add_ext(exts, NID_ext_key_usage, "clientAuth");
	//add_ext(exts, NID_ext_key_usage, "codeSigning");		//code sign

	X509_REQ_add_extensions(x509Req.get(), exts);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	BYTE* p = nullptr;
	OpenSSL_add_all_algorithms();	// must need it
									//test code
	EC_KEY_ptr eckey(nullptr, EC_KEY_free);
	eckey.reset(EC_KEY_new_by_curve_name(NID_sm2p256v1));

	EC_KEY_generate_key(eckey.get());

	EVP_PKEY* userPubKey = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(userPubKey, eckey.get());

	X509_REQ_set_pubkey(x509Req.get(), userPubKey);

	if (0 != SavePrivateKey(userPubKey, nullptr))
	{
		return 5;
	}

	X509_REQ_sign(x509Req.get(), userPubKey, EVP_sm3());

	auto pP10Len = i2d_X509_REQ(x509Req.get(), NULL);

	std::unique_ptr<BYTE> pP10Data(new BYTE[pP10Len]);
	p = pP10Data.get();
	pP10Len = i2d_X509_REQ(x509Req.get(), &p);

	*lP10Base64Datalen = base64_encode((char*)pP10Data.get(), pP10Len, pP10Base64Data);

	return 0;
}

SKFDOIT_API DWORD fnSaveSM2CertBySoft(IN char* certBase64, IN char* pPfxPath, IN char* pPassWord)
{
	if (!check_char_ptr(certBase64) || !check_char_ptr(pPfxPath) || !check_char_ptr(pPassWord))
	{
		return 1;
	}

	auto certBase64Len = strlen(certBase64);
	auto certLen = certBase64Len * 6 / 8 + 100;
	std::unique_ptr<unsigned char> pCertData(new unsigned char[certLen]);
	certLen = base64_decode(certBase64, pCertData.get());
	if (0 >= certLen)
		return 1;
	unsigned char* p = nullptr;
	p = pCertData.get();

	OpenSSL_add_all_algorithms();	// must need it

	char szkPrivKeyFile_user[MAX_PATH] = { 0 };
	//AddTempPath(szkPrivKeyFile_user, kPrivKeyFile_user);
	strcat(szkPrivKeyFile_user, kPrivKeyFile_user);

	char szCertFile_user[MAX_PATH] = { 0 };
	strcat(szCertFile_user, keycertPath);
	strcat(szCertFile_user, pPfxPath);

	BIO_ptr in(nullptr, BIO_free);
	in.reset(BIO_new_file(szkPrivKeyFile_user, "r"));
	if (!in) {
		return 4;
	}

	EVP_PKEY_ptr PrivateKey(nullptr, EVP_PKEY_free);
	EVP_PKEY* Key = PEM_read_bio_PrivateKey(in.get(), nullptr, nullptr, nullptr);
	PrivateKey.reset(Key);

	X509_ptr x509Cert(nullptr, X509_free);
	X509* cert = d2i_X509(nullptr, (const unsigned char **)&p, certLen);
	CHECK_OPENSSL_BOJECT(cert);
	x509Cert.reset(cert);

	PKCS12_ptr p12(nullptr, PKCS12_free);
	p12.reset(PKCS12_create((char*)pPassWord, nullptr, PrivateKey.get(), x509Cert.get(), nullptr, 0, 0, 0, 0, 0));
	CHECK_OPENSSL_BOJECT(p12.get());
	auto out = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new(BIO_s_file()), BIO_free);
	BIO_write_filename(out.get(), (void*)(szCertFile_user));
	auto ret = i2d_PKCS12_bio(out.get(), p12.get());
	if (1 != ret)
	{
		return 6;
	}

	return 0;
}