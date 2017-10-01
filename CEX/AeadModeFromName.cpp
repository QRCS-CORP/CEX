#include "AeadModeFromName.h"
#include "BlockCipherFromName.h"
#include "EAX.h"
#include "GCM.h"
#include "OCB.h"

NAMESPACE_HELPER

IAeadMode* AeadModeFromName::GetInstance(AeadModes CipherType, IBlockCipher* Engine)
{
	try
	{
		switch (CipherType)
		{
		case Enumeration::AeadModes::EAX:
			return new Cipher::Symmetric::Block::Mode::EAX(Engine);
		case Enumeration::AeadModes::GCM:
			return new Cipher::Symmetric::Block::Mode::GCM(Engine);
		case Enumeration::AeadModes::OCB:
			return new Cipher::Symmetric::Block::Mode::OCB(Engine);
		default:
			throw Exception::CryptoException("AeadModeFromName:GetInstance", "The AEAD cipher mode is not supported!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("AeadModeFromName:GetInstance", "The symmetric cipher mode is unavailable!", std::string(ex.what()));
	}
}

IAeadMode* AeadModeFromName::GetInstance(AeadModes CipherType, BlockCiphers EngineType)
{
	try
	{
		IBlockCipher* cipher = BlockCipherFromName::GetInstance(EngineType);

		switch (CipherType)
		{
		case Enumeration::AeadModes::EAX:
			return new Cipher::Symmetric::Block::Mode::EAX(cipher);
		case Enumeration::AeadModes::GCM:
			return new Cipher::Symmetric::Block::Mode::GCM(cipher);
		case Enumeration::AeadModes::OCB:
			return new Cipher::Symmetric::Block::Mode::OCB(cipher);
		default:
			throw Exception::CryptoException("AeadModeFromName:GetInstance", "The AEAD cipher mode is not supported!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("AeadModeFromName:GetInstance", "The block cipher mode is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND