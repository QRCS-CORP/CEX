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

	try
	{
	switch (CipherType)
	{
		case Enumeration::CipherModes::CTR:
			return new CTR(Engine);
		case Enumeration::CipherModes::CBC:
			return new CBC(Engine);
		case Enumeration::CipherModes::CFB:
			return new CFB(Engine);
		case Enumeration::CipherModes::ICM:
			return new ICM(Engine);
		case Enumeration::CipherModes::OFB:
			return new OFB(Engine);
		default:
			throw Exception::CryptoException("CipherModeFromName:GetInstance", "The cipher mode is not supported!");
	}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("CipherModeFromName:GetInstance", "The symmetric cipher mode is unavailable!", std::string(ex.what()));
	}
}

ICipherMode* CipherModeFromName::GetInstance(CipherModes CipherType, BlockCiphers EngineType)
{
	using namespace Cipher::Symmetric::Block::Mode;

	try
	{
		IBlockCipher* cipher = BlockCipherFromName::GetInstance(EngineType);

		switch (CipherType)
		{
		case Enumeration::CipherModes::CTR:
			return new CTR(cipher);
		case Enumeration::CipherModes::CBC:
			return new CBC(cipher);
		case Enumeration::CipherModes::CFB:
			return new CFB(cipher);
		case Enumeration::CipherModes::ICM:
			return new ICM(cipher);
		case Enumeration::CipherModes::OFB:
			return new OFB(cipher);
		default:
			throw Exception::CryptoException("CipherModeFromName:GetInstance", "The cipher mode is not supported!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("CipherModeFromName:GetInstance", "The block cipher mode is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND