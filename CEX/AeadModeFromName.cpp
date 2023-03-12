#include "AeadModeFromName.h"
#include "BlockCipherFromName.h"
#include "CryptoCipherModeException.h"
#include "CryptoSymmetricException.h"
#include "GCM.h"
#include "HBA.h"

NAMESPACE_HELPER

using Exception::CryptoCipherModeException;
using Exception::CryptoSymmetricException;
using Enumeration::ErrorCodes;
using Enumeration::StreamAuthenticators;
using Cipher::Block::Mode::GCM;
using Cipher::Block::Mode::HBA;

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
			case AeadModes::GCM:
			{
				mptr = new GCM(Cipher); 
				break;
			}
			case AeadModes::HBAH256:
			{
				mptr = new HBA(Cipher, StreamAuthenticators::HMACSHA2256); 
				break;
			}
			case AeadModes::HBAH512:
			{
				mptr = new HBA(Cipher, StreamAuthenticators::HMACSHA2512); 
				break;
			}
			case AeadModes::HBAS256:
			{
				mptr = new HBA(Cipher, StreamAuthenticators::KMAC256); 
				break;
			}
			case AeadModes::HBAS512:
			{
				mptr = new HBA(Cipher, StreamAuthenticators::KMAC512); 
				break;
			}
			default:
			{
				// invalid param
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
			case AeadModes::GCM:
			{
				mptr = new GCM(CipherType); 
				break;
			}
			case AeadModes::HBAH256:
			{
				mptr = new HBA(CipherType, StreamAuthenticators::HMACSHA2256); 
				break;
			}
			case AeadModes::HBAH512:
			{
				mptr = new HBA(CipherType, StreamAuthenticators::HMACSHA2512); 
				break;
			}
			case AeadModes::HBAS256:
			{
				mptr = new HBA(CipherType, StreamAuthenticators::KMAC256); 
				break;
			}
			case AeadModes::HBAS512:
			{
				mptr = new HBA(CipherType, StreamAuthenticators::KMAC512); 
				break;
			}
			default:
			{
				// invalid param
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
