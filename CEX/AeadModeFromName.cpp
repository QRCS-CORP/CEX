#include "AeadModeFromName.h"
#include "BlockCipherFromName.h"
#include "EAX.h"
#include "GCM.h"
#include "OCB.h"

NAMESPACE_HELPER

IAeadMode* AeadModeFromName::GetInstance(AeadModes CipherType, IBlockCipher* Engine)
{
	IAeadMode* aeadPtr;

	try
	{
		switch (CipherType)
		{
			case Enumeration::AeadModes::EAX:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::EAX(Engine);
				break;
			}
			case Enumeration::AeadModes::GCM:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::GCM(Engine);
				break;
			}
			case Enumeration::AeadModes::OCB:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::OCB(Engine);
				break;
			}
			default:
			{
				throw CryptoException("AeadModeFromName:GetInstance", "The AEAD cipher mode is not supported!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("AeadModeFromName:GetInstance", "The symmetric cipher mode is unavailable!", std::string(ex.what()));
	}

	return aeadPtr;
}

IAeadMode* AeadModeFromName::GetInstance(AeadModes CipherType, BlockCiphers EngineType)
{
	IAeadMode* aeadPtr;
	IBlockCipher* cprPtr = BlockCipherFromName::GetInstance(EngineType);

	try
	{
		switch (CipherType)
		{
			case Enumeration::AeadModes::EAX:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::EAX(cprPtr);
				break;
			}
			case Enumeration::AeadModes::GCM:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::GCM(cprPtr);
				break;
			}
			case Enumeration::AeadModes::OCB:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::OCB(cprPtr);
				break;
			}
			default:
			{		
				if (cprPtr != nullptr)
				{
					delete cprPtr;
				}
				throw CryptoException("AeadModeFromName:GetInstance", "The AEAD cipher mode is not supported!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		if (cprPtr != nullptr)
		{
			delete cprPtr;
		}
		throw CryptoException("AeadModeFromName:GetInstance", "The block cipher mode is unavailable!", std::string(ex.what()));
	}

	return aeadPtr;
}

NAMESPACE_HELPEREND
