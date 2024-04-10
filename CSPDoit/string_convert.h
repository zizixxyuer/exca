#pragma once

#include "stdafx.h"
#include <string>
#include <memory>
#include <vector>

#include <openssl/evp.h>

typedef std::basic_string<char>		StringA;
typedef std::basic_string<wchar_t>	StringW;

#define stdString std::wstring

StringA ToStringA(const StringA& _strFrom, UINT _FromCodePage = CP_ACP, UINT _ToCodePage = CP_ACP);
StringA ToStringA(const StringW& _strFrom, UINT _FromCodePage = CP_ACP, UINT _ToCodePage = CP_ACP);

StringW ToStringW(const StringA& _strFrom, UINT _FromCodePage = CP_ACP, UINT _ToCodePage = CP_ACP);
StringW ToStringW(const StringW& _strFrom, UINT _FromCodePage = CP_ACP, UINT _ToCodePage = CP_ACP);

static inline stdString ToStdString(const StringW& _strFrom, UINT _FromCodePage, UINT _ToCodePage)
{
	return ToStringW(_strFrom, _FromCodePage, _ToCodePage);
}

static inline stdString ToStdString(const StringA& _strFrom, UINT _FromCodePage, UINT _ToCodePage)
{
	return ToStringW(_strFrom, _FromCodePage, _ToCodePage);
}

long base64_encode(char *inData, long inLen, char* outData);
long base64_decode(char *inData, unsigned char *outData);
