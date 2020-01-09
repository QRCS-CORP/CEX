#include "AeadModeFromName.h"
#include "BlockCipherFromName.h"
#include "CryptoCipherModeException.h"
#include "CryptoSymmetricException.h"
#include "HBA.h"

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
			case AeadModes::HBAH256:
			{
				mptr = new HBA(Cipher, Enumeration::StreamAuthenticators::HMACSHA256);
				break;
			}
			case AeadModes::HBAH512:
			{
				mptr = new HBA(Cipher, Enumeration::StreamAuthenticators::HMACSHA512);
				break;
			}
			case AeadModes::HBAS256:
			{
				mptr = new HBA(Cipher, Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case AeadModes::HBAS512:
			{
				mptr = new HBA(Cipher, Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case AeadModes::HBAS1024:
			{
				mptr = new HBA(Cipher, Enumeration::StreamAuthenticators::KMAC1024);
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
		case AeadModes::HBAH256:
		{
			mptr = new HBA(CipherType, Enumeration::StreamAuthenticators::HMACSHA256);
			break;
		}
		case AeadModes::HBAH512:
		{
			mptr = new HBA(CipherType, Enumeration::StreamAuthenticators::HMACSHA512);
			break;
		}
		case AeadModes::HBAS256:
		{
			mptr = new HBA(CipherType, Enumeration::StreamAuthenticators::KMAC256);
			break;
		}
		case AeadModes::HBAS512:
		{
			mptr = new HBA(CipherType, Enumeration::StreamAuthenticators::KMAC512);
			break;
		}
		case AeadModes::HBAS1024:
		{
			mptr = new HBA(CipherType, Enumeration::StreamAuthenticators::KMAC1024);
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
