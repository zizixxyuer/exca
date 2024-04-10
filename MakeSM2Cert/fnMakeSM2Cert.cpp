#include "stdafx.h"
#include "MakeSM2Cert.h"
#include "string_convert.h"

#include <algorithm>
#include <codecvt>
#include <functional>
#include <memory>
#include <vector>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define CHECK_OPENSSL_BOJECT(obj) do {\
	if (!obj) {\
		return 5;\
	}\
}while(0)

#define SHOULD_OPT_FAILED(ret) do{\
	if (ret == 0) {\
		return 3;\
	}\
}while(0)

static const char* kCertFile = "data_sm2\\ca.crt";
static const char* kPrivKeyFile = "data_sm2\\private.key";
static const char* kSerinalFile = "data_sm2\\serinal.txt";

using X509_NAME_ptr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using BIO_ptr = std::unique_ptr < BIO, decltype(&BIO_free)>;
using  utf8_cvt = std::codecvt_utf8<wchar_t>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using ASN1_INTEGER_ptr = std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using ASN1_TIME_ptr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)>;

int LoadCA(X509** ca, EVP_PKEY** key)
{
	BIO_ptr in(nullptr, BIO_free);

	in.reset(BIO_new_file(kCertFile, "r"));
	if (!in) {
		return 4;
	}
	*ca = PEM_read_bio_X509(in.get(), nullptr, nullptr, nullptr);
	if (*ca == nullptr) {
		return 2;
	}

	in.reset(BIO_new_file(kPrivKeyFile, "r"));
	if (!in) {
		return 4;
	}

	std::wstring_convert<utf8_cvt, wchar_t> wstr_utf8_cvt;
	in.reset(BIO_new_file(kPrivKeyFile, "r"));
	auto pwd = wstr_utf8_cvt.to_bytes(_T("Abcd1234"));
	*key = PEM_read_bio_PrivateKey(in.get(), nullptr, nullptr, (void*)pwd.c_str());
	if (*key == nullptr) {
		return 4;
	}

	if (X509_verify(*ca, *key) <= 0) {
		return 4;
	}

	return 0;
}

ASN1_INTEGER* LoadUserSerinal(const char* serinalFile) {
	ASN1_INTEGER* sn = ASN1_INTEGER_new();
	BIO_ptr bio(BIO_new(BIO_s_file()), BIO_free);
	const int bufSize = 0x40;
	char buf[bufSize + 1];
	BN_ptr bn(BN_new(), BN_free);

	if (BIO_read_filename(bio.get(), serinalFile) <= 0) {
		BN_rand(bn.get(), 4 * 8, 0, 0);
		BN_lshift(bn.get(), bn.get(), 4 * 8);
	}
	else if (BIO_gets(bio.get(), buf, bufSize) <= 0) {
		BN_rand(bn.get(), 4 * 8, 0, 0);
		BN_lshift(bn.get(), bn.get(), 4 * 8);
	}
	else {
		auto p = bn.get();
		if (!BN_hex2bn(&p, buf)) {
			BN_rand(bn.get(), 4 * 8, 0, 0);
			BN_lshift(bn.get(), bn.get(), 4 * 8);
		}
	}

	// incremante
	BN_add_word(bn.get(), 1);
	// bn -> hex string
	auto hex = BN_bn2hex(bn.get());

	// save to file
	bio.reset(BIO_new_file(serinalFile, "w"));
	BIO_puts(bio.get(), hex);
	OPENSSL_free(hex);
	sn = BN_to_ASN1_INTEGER(bn.get(), nullptr);
	return sn;
}

BOOL check_char_ptr(char* p)
{
	if (NULL == p || strlen(p) == 0)
	{
		return FALSE;
	}

	return TRUE;
}

MAKESM2CERT_API DWORD fnMakeSM2CertByP10(IN char* p10Base64Data, OUT char* pCertData, OUT long* lCertLen)
{
	if (!check_char_ptr(p10Base64Data))
	{
		return 1;
	}

	int i = 0;
	auto p10Base64Len = strlen(p10Base64Data);
	auto p10Len = p10Base64Len * 6 / 8 + 100;
	std::unique_ptr<unsigned char> pP10Data(new unsigned char[p10Len]);
	p10Len = base64_decode(p10Base64Data, pP10Data.get());
	if (0 >= p10Len)
		return 1;

	unsigned char* p = nullptr;
	p = pP10Data.get();
	X509_REQ *x509Req = d2i_X509_REQ(nullptr, (const unsigned char **)&p, p10Len);
	CHECK_OPENSSL_BOJECT(x509Req);

	EVP_PKEY *userPubKey = X509_REQ_get_pubkey(x509Req);
	CHECK_OPENSSL_BOJECT(userPubKey);

	//verify X509_REQ
	OpenSSL_add_all_algorithms();
	auto ret = X509_REQ_verify(x509Req, userPubKey);
	if (0 >= ret)
		return 2;

	X509_NAME *x509Name = X509_REQ_get_subject_name(x509Req);
	CHECK_OPENSSL_BOJECT(x509Name);

	X509_NAME_ptr subject(X509_NAME_new(), X509_NAME_free);

	std::vector<int> arr;

	for (i = 0; i < X509_NAME_entry_count(x509Name); i++)
	{
		X509_NAME_ENTRY *ne = X509_NAME_get_entry(x509Name, i);
		ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ne);
		auto objNID = OBJ_obj2nid(obj);
		X509_NAME_add_entry(subject.get(), ne, -1, 0);

		arr.push_back(objNID);
	}

	auto subjectAddItem = [&subject](int nid, std::string v, std::vector<int> arr) -> int {
		if (v.empty()) return 1;  //same as openssl return value
		for (auto n : arr)
		{
			if (nid == n)
			{
				return 1;
			}
		}
		return X509_NAME_add_entry_by_NID(subject.get(), nid, MBSTRING_UTF8,
			(unsigned char*)v.c_str(), v.length(), -1, 0);
	};

	// C
	ret = subjectAddItem(NID_countryName, "CN", arr);
	SHOULD_OPT_FAILED(ret);

	// S
	ret = subjectAddItem(NID_stateOrProvinceName, "BeiJing", arr);
	SHOULD_OPT_FAILED(ret);

	// L
	ret = subjectAddItem(NID_localityName, "HaiDian", arr);
	SHOULD_OPT_FAILED(ret);

	// O
	ret = subjectAddItem(NID_organizationName, "Test Technologies Co., Ltd.", arr);
	SHOULD_OPT_FAILED(ret);

	// OU
	ret = subjectAddItem(NID_organizationalUnitName, "develop", arr);
	SHOULD_OPT_FAILED(ret);

	// email
	ret = subjectAddItem(NID_pkcs9_emailAddress, "test@test.com", arr);
	SHOULD_OPT_FAILED(ret);

	// CN
	ret = subjectAddItem(NID_commonName, "test1", arr);
	SHOULD_OPT_FAILED(ret);

	X509* __ca = nullptr;
	EVP_PKEY* __ca_priv_key = nullptr;
	ret = LoadCA(&__ca, &__ca_priv_key);
	if (ret) {
		return 4;
	}

	X509_ptr ca(nullptr, X509_free);
	EVP_PKEY_ptr caPrivateKey(nullptr, EVP_PKEY_free);
	ca.reset(__ca);
	CHECK_OPENSSL_BOJECT(ca);
	caPrivateKey.reset(__ca_priv_key);
	CHECK_OPENSSL_BOJECT(caPrivateKey);

	X509_ptr cert(X509_new(), X509_free);

	ret = X509_set_pubkey(cert.get(), userPubKey);
	SHOULD_OPT_FAILED(ret);

	// sn
	ASN1_INTEGER_ptr sn(ASN1_INTEGER_new(), ASN1_INTEGER_free);
	CHECK_OPENSSL_BOJECT(sn);
	sn.reset(LoadUserSerinal(kSerinalFile));
	ret = X509_set_serialNumber(cert.get(), sn.get());
	SHOULD_OPT_FAILED(ret);

	// issuer
	ret = X509_set_issuer_name(cert.get(), X509_get_subject_name(ca.get()));
	SHOULD_OPT_FAILED(ret);

	//subject
	ret = X509_set_subject_name(cert.get(), subject.get());
	SHOULD_OPT_FAILED(ret);

	// notBefore
	ASN1_TIME_ptr notBefore(X509_time_adj_ex(nullptr, 0, 0, nullptr), ASN1_TIME_free);
	CHECK_OPENSSL_BOJECT(notBefore);
	ret = X509_set_notBefore(cert.get(), notBefore.get());
	SHOULD_OPT_FAILED(ret);


	// notAfter
	ASN1_TIME_ptr notAfter(X509_time_adj_ex(nullptr, 3650, 0, nullptr), ASN1_TIME_free);
	CHECK_OPENSSL_BOJECT(notAfter);
	ret = X509_set_notAfter(cert.get(), notAfter.get());
	SHOULD_OPT_FAILED(ret);

	//v3 ext
	//version
	ret = X509_set_version(cert.get(), 2); // v3

	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);

	X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);

	auto addExt = [](X509V3_CTX *ctx, X509 *cert, int nid, char *value) {
		X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value);
		X509_add_ext(cert, ex, -1);
		X509_EXTENSION_free(ex);
	};
	// ca
	addExt(&ctx, cert.get(), NID_basic_constraints, "critical,CA:FALSE");
	// key usage
	//addExt(&ctx, cert.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment");
	//addExt(&ctx, cert.get(), NID_key_usage, "critical,keyEncipherment,dataEncipherment");
	//addExt(&ctx, cert.get(), NID_key_usage, "critical,digitalSignature,nonRepudiation");
	// extend key usage
	//addExt(&ctx, cert.get(), NID_ext_key_usage, "clientAuth");
	// self key id
	addExt(&ctx, cert.get(), NID_subject_key_identifier, "hash");

	STACK_OF(X509_EXTENSION) *exts;
	exts = X509_REQ_get_extensions(x509Req);
	for (i = 0; i < sk_X509_EXTENSION_num(exts); i++)
	{
		ASN1_OBJECT *obj;
		X509_EXTENSION *ex;
		ex = sk_X509_EXTENSION_value(exts, i);
		obj = X509_EXTENSION_get_object(ex);

		X509_add_ext(cert.get(), ex, -1);
	}

	ret = X509_sign(cert.get(), caPrivateKey.get(), EVP_sm3());
	SHOULD_OPT_FAILED(ret);

	auto certLen = i2d_X509(cert.get(), NULL);
	std::unique_ptr<BYTE> derCert(new BYTE[certLen]);
	p = derCert.get();
	certLen = i2d_X509(cert.get(), &p);

	*lCertLen = base64_encode((char*)derCert.get(), certLen, pCertData);

	return 0;
}