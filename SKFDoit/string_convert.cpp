#include "string_convert.h"

StringA ToStringA(const StringA& _strFrom, UINT _FromCodePage, UINT _ToCodePage)
{
	// ��ͬ���룬ֱ�ӷ���
	if (_FromCodePage == _ToCodePage)
		return _strFrom;

	StringA strRet("");

	// ��ת���ɿ��ַ�(ע�⣬���ַ�ʵ������UTF-16����)
	int iSize1 = MultiByteToWideChar(_FromCodePage, 0, _strFrom.c_str(), (int)_strFrom.length(), NULL, 0);
	if (iSize1 <= 0)
		return strRet;

	++iSize1;
	wchar_t* pwszStr = new wchar_t[iSize1];
	if (NULL == pwszStr)
		return strRet;
	ZeroMemory(pwszStr, iSize1 * sizeof(wchar_t));

	MultiByteToWideChar(_FromCodePage, 0, _strFrom.c_str(), (int)_strFrom.length(), pwszStr, iSize1 /** sizeof(wchar_t)*/);

	// Ȼ����ת��Ϊ��Ҫ���ַ�����
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

// �������� _FromCodePage ��û���õģ����Դ� CP_ACP
StringA ToStringA(const StringW& _strFrom, UINT _FromCodePage, UINT _ToCodePage)
{
	StringA strRet("");

	// ֱ�ӽ����ַ���(UTF-16)ת��ΪĿ������ʽ�ĵ��ַ���
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

// �������� _ToCodePage ��û���õģ����Դ� CP_ACP
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
* @brief           base64 ���룬�����ʽ��������
*
* @param inData    Դ����
*
* @return          ����������
*/
long base64_encode(char *inData, long inLen, char* outData)
{
	if (NULL == inData)
	{
		return NULL;
	}

	int inl = 0, outl = 0, total = 0, blocksize = 0;

	// �����������ݵĳ���
	inl = inLen;

	/*
	* ���������������С
	* Base64Ҫ���ÿ����8Bit���ֽ�ת��Ϊ�ĸ�6Bit���ֽڣ�3*8 = 4*6 = 24��
	* Ȼ���6Bit������λ��λ0������ĸ�8Bit���ֽڣ�Ҳ����˵��ת������ַ��������Ͻ�Ҫ��ԭ���ĳ�1/3��
	* */
	blocksize = inl * 8 / 6 + 100;

	std::vector<char> buffer(blocksize);
	memset(&buffer[0], 0, blocksize);
	
	// �������ݽṹ
	EVP_ENCODE_CTX* e_ctx = EVP_ENCODE_CTX_new();

	// ��ʼ�����ݽṹ
	EVP_EncodeInit(e_ctx);
	
	// ����
	outl = 0;
	total = 0;
	EVP_EncodeUpdate(e_ctx, (unsigned char*)&buffer[0], &outl, (unsigned char*)inData, inl);
	total += outl;
	
	// �����ڱ����������ʱ���á���������ctx������ʣ����κβ������ݿ顣
	EVP_EncodeFinal(e_ctx, (unsigned char*)&buffer[total], &outl);
	total += outl;

	memcpy(outData, &buffer[0], total);

	EVP_ENCODE_CTX_free(e_ctx);
	return total;
}


/**
* @brief           base64 ���롣Դ�����Ǵ���ʽ�ģ�ÿ 64 �ֽ��и����з���
*
* @param inData    Դ����
*
* @return          ����������
*/
long base64_decode(char *inData, unsigned char *outData)
{
	if (NULL == inData)
	{
		return 0;
	}

	int inl, outl, total, blocksize;

	// �����������ݵĳ���
	inl = strlen(inData);

	// base64 �������� 4 �ֽ�
	if (inl < 4)
	{
		return 0;
	}

	outl = 0;
	total = 0;
	blocksize = inl * 6 / 8 + 100;

	std::unique_ptr<unsigned char> buffer(new unsigned char[blocksize]);
	memset(buffer.get(), 0, blocksize);

	// �������ݽṹ
	EVP_ENCODE_CTX* d_ctx = EVP_ENCODE_CTX_new(); 

	// ��ʼ�����ݽṹ
	EVP_DecodeInit(d_ctx);

	// ����ʱ���� -1���ɹ�ʱ���� 0 �� 1��������� 0������Ҫ����ķ���� base 64 �ַ�
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
