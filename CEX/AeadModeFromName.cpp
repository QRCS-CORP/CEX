#include "AeadModeFromName.h"
#include "BlockCipherFromName.h"
#include "EAX.h"
#include "GCM.h"
#include "OCB.h"

NAMESPACE_HELPER

IAeadMode* AeadModeFromName::GetInstance(IBlockCipher* Cipher, AeadModes CipherModeType)
{
	IAeadMode* aeadPtr = nullptr;

	try
	{
		switch (CipherModeType)
		{
			case Enumeration::AeadModes::EAX:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::EAX(Cipher);
				break;
			}
			case Enumeration::AeadModes::GCM:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::GCM(Cipher);
				break;
			}
			case Enumeration::AeadModes::OCB:
			{
				aeadPtr = new Cipher::Symmetric::Block::Mode::OCB(Cipher);
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

IAeadMode* AeadModeFromName::GetInstance(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, AeadModes CipherModeType)
{
	IAeadMode* aeadPtr = nullptr;
	IBlockCipher* cprPtr = nullptr;

	try
	{
		BlockCipherFromName::GetInstance(CipherType, CipherExtensionType);

		switch (CipherModeType)
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
