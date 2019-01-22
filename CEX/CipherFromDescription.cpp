#include "CipherFromDescription.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "CryptoCipherModeException.h"
#include "CryptoSymmetricCipherException.h"

NAMESPACE_HELPER

using Exception::CryptoCipherModeException;
using Exception::CryptoSymmetricCipherException;
using Enumeration::ErrorCodes;

const std::string CipherFromDescription::CLASS_NAME("CipherFromDescription");

ICipherMode* CipherFromDescription::GetInstance(CipherDescription &Description)
{
	IBlockCipher* cptr;
	ICipherMode* mptr;

	cptr = nullptr;
	mptr = nullptr;

	try
	{
		cptr = BlockCipherFromName::GetInstance(Description.CipherType(), Description.CipherExtensionType());
		mptr = CipherModeFromName::GetInstance(cptr, Description.CipherModeType());
	}
	catch (CryptoCipherModeException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (CryptoSymmetricCipherException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (CryptoException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		if (cptr != nullptr)
		{
			delete cptr;
		}

		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), Enumeration::ErrorCodes::UnKnown);
	}

	return mptr;
}

NAMESPACE_HELPEREND
