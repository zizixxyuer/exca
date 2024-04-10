#include "string_convert.h"

StringA ToStringA(const StringA& _strFrom, UINT _FromCodePage, UINT _ToCodePage)
{
	// 相同编码，直接返回
	if (_FromCodePage == _ToCodePage)
		return _strFrom;

	StringA strRet("");

	// 先转换成宽字符(注意，宽字符实际上是UTF-16编码)
	int iSize1 = MultiByteToWideChar(_FromCodePage, 0, _strFrom.c_str(), (int)_strFrom.length(), NULL, 0);
	if (iSize1 <= 0)
		return strRet;

	++iSize1;
	wchar_t* pwszStr = new wchar_t[iSize1];
	if (NULL == pwszStr)
		return strRet;
	ZeroMemory(pwszStr, iSize1 * sizeof(wchar_t));

	MultiByteToWideChar(_FromCodePage, 0, _strFrom.c_str(), (int)_strFrom.length(), pwszStr, iSize1 /** sizeof(wchar_t)*/);

	// 然后将其转换为需要的字符编码
	int iSize2 = WideCharToMultiByte(_ToCodePage, 0, pwszStr, -1, NULL, 0, NULL, NULL);
	if (iSize2 <= 0)
	{
		delete[] pwszStr;
		return strRet;
	}

	++iSize2;
	char* pszStr = new char[iSize2];
	if (NULL == pszStr)
	{
		delete[] pwszStr;
		return strRet;
	}
	ZeroMemory(pszStr, iSize2);

	WideCharToMultiByte(_ToCodePage, 0, pwszStr, -1, pszStr, iSize2, NULL, NULL);

	strRet = pszStr;
	delete[] pwszStr;
	delete[] pszStr;

	return strRet;
}

// 本函数中 _FromCodePage 是没有用的，可以传 CP_ACP
StringA ToStringA(const StringW& _strFrom, UINT _FromCodePage, UINT _ToCodePage)
{
	StringA strRet("");

	// 直接将宽字符串(UTF-16)转换为目标编码格式的单字符串
	int iSize = WideCharToMultiByte(_ToCodePage, 0, _strFrom.c_str(), -1, NULL, 0, NULL, NULL);
	if (iSize <= 0)
	{
		return strRet;
	}

	++iSize;
	char* pszStr = new char[iSize];
	if (NULL == pszStr)
	{
		return strRet;
	}
	ZeroMemory(pszStr, iSize);

	WideCharToMultiByte(_ToCodePage, 0, _strFrom.c_str(), -1, pszStr, iSize, NULL, NULL);

	strRet = pszStr;
	delete[] pszStr;

	//	return strRet;
	//	if(_FromCodePage == _ToCodePage)
	return strRet;

	//	return ToStringA(strRet, _FromCodePage, _ToCodePage);
}

// 本函数中 _ToCodePage 是没有用的，可以传 CP_ACP
StringW ToStringW(const StringA& _strFrom, UINT _FromCodePage, UINT _ToCodePage)
{
	StringW strRet(L"");

	int iSize = MultiByteToWideChar(_FromCodePage, 0, _strFrom.c_str(), (int)_strFrom.length(), NULL, 0);
	if (iSize <= 0)
		return strRet;

	++iSize;
	wchar_t* pwszStr = new wchar_t[iSize];
	if (NULL == pwszStr)
		return L"";
	ZeroMemory(pwszStr, iSize * sizeof(wchar_t));

	MultiByteToWideChar(_FromCodePage, 0, _strFrom.c_str(), (int)_strFrom.length(), pwszStr, iSize);

	strRet = pwszStr;
	delete[] pwszStr;
	pwszStr = NULL;

	return strRet;
}

StringW ToStringW(const StringW& _strFrom, UINT _FromCodePage, UINT _ToCodePage)
{
	return _strFrom;
}


/**
* @brief           base64 编码，输出格式化的数据
*
* @param inData    源数据
*
* @return          编码后的数据
*/
long base64_encode(char *inData, long inLen, char* outData)
{
	if (NULL == inData)
	{
		return NULL;
	}

	int inl = 0, outl = 0, total = 0, blocksize = 0;

	// 计算输入数据的长度
	inl = inLen;

	/*
	* 计算输出缓冲区大小
	* Base64要求把每三个8Bit的字节转换为四个6Bit的字节（3*8 = 4*6 = 24）
	* 然后把6Bit再添两位高位0，组成四个8Bit的字节，也就是说，转换后的字符串理论上将要比原来的长1/3。
	* */
	blocksize = inl * 8 / 6 + 100;

	std::vector<char> buffer(blocksize);
	memset(&buffer[0], 0, blocksize);
	
	// 创建数据结构
	EVP_ENCODE_CTX* e_ctx = EVP_ENCODE_CTX_new();

	// 初始化数据结构
	EVP_EncodeInit(e_ctx);
	
	// 编码
	outl = 0;
	total = 0;
	EVP_EncodeUpdate(e_ctx, (unsigned char*)&buffer[0], &outl, (unsigned char*)inData, inl);
	total += outl;
	
	// 必须在编码操作结束时调用。它将处理ctx对象中剩余的任何部分数据块。
	EVP_EncodeFinal(e_ctx, (unsigned char*)&buffer[total], &outl);
	total += outl;

	memcpy(outData, &buffer[0], total);

	EVP_ENCODE_CTX_free(e_ctx);
	return total;
}


/**
* @brief           base64 解码。源数据是带格式的（每 64 字节有个换行符）
*
* @param inData    源数据
*
* @return          解码后的数据
*/
long base64_decode(char *inData, unsigned char *outData)
{
	if (NULL == inData)
	{
		return 0;
	}

	int inl, outl, total, blocksize;

	// 计算输入数据的长度
	inl = strlen(inData);

	// base64 密文至少 4 字节
	if (inl < 4)
	{
		return 0;
	}

	outl = 0;
	total = 0;
	blocksize = inl * 6 / 8 + 100;

	std::unique_ptr<unsigned char> buffer(new unsigned char[blocksize]);
	memset(buffer.get(), 0, blocksize);

	// 创建数据结构
	EVP_ENCODE_CTX* d_ctx = EVP_ENCODE_CTX_new(); 

	// 初始化数据结构
	EVP_DecodeInit(d_ctx);

	// 出错时返回 -1，成功时返回 0 或 1。如果返回 0，则不需要更多的非填充 base 64 字符
	if (-1 == EVP_DecodeUpdate(d_ctx, (unsigned char*)buffer.get(), &outl, (unsigned char*)inData, inl))
	{
		goto err;
	}

	total += outl;

	if (-1 == EVP_DecodeFinal(d_ctx, (unsigned char*)buffer.get(), &outl))
	{
		goto err;
	}
	total += outl;

	EVP_ENCODE_CTX_free(d_ctx);
	memcpy(outData, buffer.get(), total);
	return total;
err:
	EVP_ENCODE_CTX_free(d_ctx);
	return 0;
}
