#include "CipherModeFromName.h"
#include "BlockCipherFromName.h"
#include "CTR.h"
#include "CBC.h"
#include "CFB.h"
#include "CryptoCipherModeException.h"
#include "CryptoSymmetricCipherException.h"
#include "ICM.h"
#include "OFB.h"

NAMESPACE_HELPER

using Enumeration::CipherModes;
using Exception::CryptoCipherModeException;
using Exception::CryptoSymmetricCipherException;
using Enumeration::ErrorCodes;

const std::string CipherModeFromName::CLASS_NAME("CipherModeFromName");

ICipherMode* CipherModeFromName::GetInstance(IBlockCipher* Cipher, CipherModes CipherModeType)
{
	using namespace Cipher::Block::Mode;

	ICipherMode* mptr;

	mptr = nullptr;

	try
	{
		switch (CipherModeType)
		{
			case CipherModes::CTR:
			{
				mptr = new CTR(Cipher);
				break;
			}
			case CipherModes::CBC:
			{
				mptr = new CBC(Cipher);
				break;
			}
			case CipherModes::CFB:
			{
				mptr = new CFB(Cipher);
				break;
			}
			case CipherModes::ICM:
			{
				mptr = new ICM(Cipher);
				break;
			}
			case CipherModes::OFB:
			{
				mptr = new OFB(Cipher);
				break;
			}
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The cipher engine is not supported!"), ErrorCodes::InvalidParam);
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

ICipherMode* CipherModeFromName::GetInstance(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, CipherModes CipherModeType)
{
	using namespace Cipher::Block::Mode;

	IBlockCipher* cptr;
	ICipherMode* mptr;

	cptr = nullptr;
	mptr = nullptr;

	try
	{
		cptr = BlockCipherFromName::GetInstance(CipherType, CipherExtensionType);

		switch (CipherModeType)
		{
			case CipherModes::CTR:
			{
				mptr = new CTR(cptr);
				break;
			}
			case CipherModes::CBC:
			{
				mptr = new CBC(cptr);
				break;
			}
			case CipherModes::CFB:
			{
				mptr = new CFB(cptr);
				break;
			}
			case CipherModes::ICM:
			{
				mptr = new ICM(cptr);
				break;
			}
			case CipherModes::OFB:
			{
				mptr = new OFB(cptr);
				break;
			}
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The cipher type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoSymmetricCipherException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (CryptoCipherModeException &ex)
	{
		if (cptr != nullptr)
		{
			delete cptr;
		}

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

		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return mptr;
}

NAMESPACE_HELPEREND
