#include "CipherModeFromName.h"
#include "CTR.h"
#include "CBC.h"
#include "CFB.h"
#include "OFB.h"

NAMESPACE_HELPER

CEX::Cipher::Symmetric::Block::Mode::ICipherMode* CipherModeFromName::GetInstance(CEX::Enumeration::CipherModes CipherType, CEX::Cipher::Symmetric::Block::IBlockCipher* Engine)
{
	switch (CipherType)
	{
		case CEX::Enumeration::CipherModes::CTR:
			return new CEX::Cipher::Symmetric::Block::Mode::CTR(Engine);
		case CEX::Enumeration::CipherModes::CBC:
			return new CEX::Cipher::Symmetric::Block::Mode::CBC(Engine);
		case CEX::Enumeration::CipherModes::CFB:
			return new CEX::Cipher::Symmetric::Block::Mode::CFB(Engine);
		case CEX::Enumeration::CipherModes::OFB:
			return new CEX::Cipher::Symmetric::Block::Mode::OFB(Engine);
		default:
			throw CEX::Exception::CryptoException("CipherModeFromName:GetInstance", "The cipher mode is not supported!");
	}
}

NAMESPACE_HELPEREND