#include "CipherFromDescription.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "CryptoCipherModeException.h"
#include "CryptoSymmetricCipherException.h"

NAMESPACE_HELPER

using Exception::CryptoCipherModeException;
using Exception::CryptoSymmetricCipherException;
using Enumeration::ErrorCodes;

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
		throw CryptoException(std::string("CipherFromDescription"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (CryptoSymmetricCipherException &ex)
	{
		throw CryptoException(std::string("CipherFromDescription"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (CryptoException &ex)
	{
		throw CryptoException(std::string("CipherFromDescription"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		if (cptr != nullptr)
		{
			delete cptr;
		}

		throw CryptoException(std::string("CipherFromDescription"), std::string("GetInstance"), std::string(ex.what()), Enumeration::ErrorCodes::UnKnown);
	}

	return mptr;
}

NAMESPACE_HELPEREND
