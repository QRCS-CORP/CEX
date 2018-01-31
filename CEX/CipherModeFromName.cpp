#include "CipherModeFromName.h"
#include "BlockCipherFromName.h"
#include "CTR.h"
#include "CBC.h"
#include "CFB.h"
#include "ICM.h"
#include "OFB.h"

NAMESPACE_HELPER

ICipherMode* CipherModeFromName::GetInstance(CipherModes CipherType, IBlockCipher* Engine)
{
	using namespace Cipher::Symmetric::Block::Mode;

	ICipherMode* mdePtr;

	try
	{
		switch (CipherType)
		{
			case Enumeration::CipherModes::CTR:
			{
				mdePtr = new CTR(Engine);
				break;
			}
			case Enumeration::CipherModes::CBC:
			{
				mdePtr = new CBC(Engine);
				break;
			}
			case Enumeration::CipherModes::CFB:
			{
				mdePtr = new CFB(Engine);
				break;
			}
			case Enumeration::CipherModes::ICM:
			{
				mdePtr = new ICM(Engine);
				break;
			}
			case Enumeration::CipherModes::OFB:
			{
				mdePtr = new OFB(Engine);
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

ICipherMode* CipherModeFromName::GetInstance(CipherModes CipherType, BlockCiphers EngineType)
{
	using namespace Cipher::Symmetric::Block::Mode;

	ICipherMode* mdePtr;
	IBlockCipher* cprPtr = BlockCipherFromName::GetInstance(EngineType);

	try
	{
		switch (CipherType)
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
