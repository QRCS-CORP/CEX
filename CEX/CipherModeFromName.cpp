#include "CipherModeFromName.h"
#include "BlockCipherFromName.h"
#include "CTR.h"
#include "CBC.h"
#include "CFB.h"
#include "ICM.h"
#include "OFB.h"

NAMESPACE_HELPER

ICipherMode* CipherModeFromName::GetInstance(IBlockCipher* Cipher, CipherModes CipherModeType)
{
	using namespace Cipher::Symmetric::Block::Mode;

	ICipherMode* mdePtr = nullptr;

	try
	{
		switch (CipherModeType)
		{
			case Enumeration::CipherModes::CTR:
			{
				mdePtr = new CTR(Cipher);
				break;
			}
			case Enumeration::CipherModes::CBC:
			{
				mdePtr = new CBC(Cipher);
				break;
			}
			case Enumeration::CipherModes::CFB:
			{
				mdePtr = new CFB(Cipher);
				break;
			}
			case Enumeration::CipherModes::ICM:
			{
				mdePtr = new ICM(Cipher);
				break;
			}
			case Enumeration::CipherModes::OFB:
			{
				mdePtr = new OFB(Cipher);
				break;
			}
			default:
			{
				throw CryptoException("CipherModeFromName:GetInstance", "The cipher mode is not supported!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("CipherModeFromName:GetInstance", "The symmetric cipher mode is unavailable!", std::string(ex.what()));
	}

	return mdePtr;
}

ICipherMode* CipherModeFromName::GetInstance(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, CipherModes CipherModeType)
{
	using namespace Cipher::Symmetric::Block::Mode;

	ICipherMode* mdePtr = nullptr;
	IBlockCipher* cprPtr = nullptr;

	try
	{
		cprPtr = BlockCipherFromName::GetInstance(CipherType, CipherExtensionType);

		switch (CipherModeType)
		{
			case Enumeration::CipherModes::CTR:
			{
				mdePtr = new CTR(cprPtr);
				break;
			}
			case Enumeration::CipherModes::CBC:
			{
				mdePtr = new CBC(cprPtr);
				break;
			}
			case Enumeration::CipherModes::CFB:
			{
				mdePtr = new CFB(cprPtr);
				break;
			}
			case Enumeration::CipherModes::ICM:
			{
				mdePtr = new ICM(cprPtr);
				break;
			}
			case Enumeration::CipherModes::OFB:
			{
				mdePtr = new OFB(cprPtr);
				break;
			}
			default:
			{
				if (cprPtr != nullptr)
				{
					delete cprPtr;
				}
				throw CryptoException("CipherModeFromName:GetInstance", "The cipher mode is not supported!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		if (cprPtr != nullptr)
		{
			delete cprPtr;
		}
		throw CryptoException("CipherModeFromName:GetInstance", "The block cipher mode is unavailable!", std::string(ex.what()));
	}

	return mdePtr;
}

NAMESPACE_HELPEREND
