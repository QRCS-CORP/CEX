#include "CipherFromDescription.h"
#include "BlockCipherFromName.h"
#include "CryptoException.h"
#include "CipherModeFromName.h"

NAMESPACE_HELPER

using CEX::Common::CipherDescription;
using CEX::Enumeration::SymmetricEngines;

CEX::Cipher::Symmetric::Block::Mode::ICipherMode* CipherFromDescription::GetInstance(CEX::Common::CipherDescription &Description)
{
	switch (Description.EngineType())
	{
	case SymmetricEngines::RHX:
	case SymmetricEngines::SHX:
	case SymmetricEngines::THX:
	{
		return CEX::Helper::CipherModeFromName::GetInstance(Description.CipherType(),
			CEX::Helper::BlockCipherFromName::GetInstance((CEX::Enumeration::BlockCiphers)Description.EngineType(),
				(uint)Description.BlockSize(), (uint)Description.RoundCount(), Description.KdfEngine()));
	}
	default:
#if defined(ENABLE_CPPEXCEPTIONS)
		throw CEX::Exception::CryptoException("CipherFromDescription:GetInstance", "The symmetric cipher is not recognized!");
#else
		return 0;
#endif
	}
}

NAMESPACE_HELPEREND