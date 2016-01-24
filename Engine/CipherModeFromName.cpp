#include "CipherModeFromName.h"
#include "CTR.h"
#include "CBC.h"
#include "CFB.h"
#include "OFB.h"

NAMESPACE_HELPER

using namespace CEX::Cipher::Symmetric::Block::Mode;

ICipherMode* CipherModeFromName::GetInstance(CipherModes CipherType, IBlockCipher* Engine)
{
	switch (CipherType)
	{
		case CipherModes::CTR:
			return new CTR(Engine);
		case CipherModes::CBC:
			return new CBC(Engine);
		case CipherModes::CFB:
			return new CFB(Engine);
		case CipherModes::OFB:
			return new OFB(Engine);
		default:
			throw CryptoException("CipherModeFromName:GetInstance", "The cipher mode is not supported!");
	}
}

NAMESPACE_HELPEREND