#include "AeadModeFromName.h"
#include "BlockCipherFromName.h"
#include "CryptoCipherModeException.h"
#include "CryptoSymmetricCipherException.h"
#include "EAX.h"
#include "GCM.h"
#include "OCB.h"

NAMESPACE_HELPER

using Exception::CryptoCipherModeException;
using Exception::CryptoSymmetricCipherException;
using Enumeration::ErrorCodes;

IAeadMode* AeadModeFromName::GetInstance(IBlockCipher* Cipher, AeadModes CipherModeType)
{
	using namespace Cipher::Block::Mode;

	IAeadMode* mptr;

	mptr = nullptr;

	try
	{
		switch (CipherModeType)
		{
			case AeadModes::EAX:
			{
				mptr = new EAX(Cipher);
				break;
			}
			case AeadModes::GCM:
			{
				mptr = new GCM(Cipher);
				break;
			}
			case AeadModes::OCB:
			{
				mptr = new OCB(Cipher);
				break;
			}
			default:
			{
				throw CryptoException(std::string("AeadModeFromName"), std::string("GetInstance"), std::string("The AEAD cipher mode is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoCipherModeException &ex)
	{
		throw CryptoException(std::string("AeadModeFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("AeadModeFromName"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return mptr;
}

IAeadMode* AeadModeFromName::GetInstance(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, AeadModes CipherModeType)
{
	using namespace Cipher::Block::Mode;

	IBlockCipher* cptr;
	IAeadMode* mptr;

	cptr = nullptr;
	mptr = nullptr;

	try
	{
		BlockCipherFromName::GetInstance(CipherType, CipherExtensionType);

		switch (CipherModeType)
		{
			case AeadModes::EAX:
			{
				mptr = new EAX(cptr);
				break;
			}
			case AeadModes::GCM:
			{
				mptr = new GCM(cptr);
				break;
			}
			case AeadModes::OCB:
			{
				mptr = new OCB(cptr);
				break;
			}
			default:
			{		
				throw CryptoCipherModeException(std::string("AeadModeFromName"), std::string("GetInstance"), std::string("The AEAD cipher mode type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoCipherModeException &ex)
	{
		if (cptr != nullptr)
		{
			delete cptr;
		}

		throw CryptoException(std::string("AeadModeFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (CryptoSymmetricCipherException &ex)
	{
		throw CryptoException(std::string("AeadModeFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		if (cptr != nullptr)
		{
			delete cptr;
		}

		throw CryptoException(std::string("AeadModeFromName"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return mptr;
}

NAMESPACE_HELPEREND
