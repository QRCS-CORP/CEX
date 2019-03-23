#include "AeadModeFromName.h"
#include "BlockCipherFromName.h"
#include "CryptoCipherModeException.h"
#include "CryptoSymmetricException.h"
#include "EAX.h"
#include "GCM.h"

NAMESPACE_HELPER

using Exception::CryptoCipherModeException;
using Exception::CryptoSymmetricException;
using Enumeration::ErrorCodes;

const std::string AeadModeFromName::CLASS_NAME("AeadModeFromName");

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
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The AEAD cipher mode is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoCipherModeException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return mptr;
}

IAeadMode* AeadModeFromName::GetInstance(BlockCiphers CipherType, AeadModes CipherModeType)
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
				mptr = new EAX(CipherType);
				break;
			}
			case AeadModes::GCM:
			{
				mptr = new GCM(CipherType);
				break;
			}
			default:
			{		
				throw CryptoCipherModeException(CLASS_NAME, std::string("GetInstance"), std::string("The AEAD cipher mode type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoCipherModeException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (CryptoSymmetricException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return mptr;
}

NAMESPACE_HELPEREND
