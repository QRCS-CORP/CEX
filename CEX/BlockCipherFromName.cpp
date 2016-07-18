#include "BlockCipherFromName.h"
#include "RHX.h"
#include "SHX.h"
#include "THX.h"

#if defined(AESNI_AVAILABLE)
#	include "AHX.h"
#	include "CpuDetect.h"
#endif

NAMESPACE_HELPER

CEX::Cipher::Symmetric::Block::IBlockCipher* BlockCipherFromName::GetInstance(CEX::Enumeration::BlockCiphers BlockCipherType)
{
	switch (BlockCipherType)
	{
		case CEX::Enumeration::BlockCiphers::AHX:
		case CEX::Enumeration::BlockCiphers::RHX:
		{
#if defined(AESNI_AVAILABLE)
			CEX::Common::CpuDetect detect;
			if (detect.AES)
				return new CEX::Cipher::Symmetric::Block::AHX();
			else
				return new CEX::Cipher::Symmetric::Block::RHX();
#else
				return new CEX::Cipher::Symmetric::Block::RHX();
#endif
		}
		case CEX::Enumeration::BlockCiphers::SHX:
			return new CEX::Cipher::Symmetric::Block::SHX();
		case CEX::Enumeration::BlockCiphers::THX:
			return new CEX::Cipher::Symmetric::Block::THX();

		default:
#if defined(ENABLE_CPPEXCEPTIONS)
			throw CEX::Exception::CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
#else
			return 0;
#endif
	}
}

CEX::Cipher::Symmetric::Block::IBlockCipher* BlockCipherFromName::GetInstance(CEX::Enumeration::BlockCiphers BlockCipherType, uint BlockSize, uint RoundCount, CEX::Enumeration::Digests KdfEngineType)
{
	switch (BlockCipherType)
	{
		case CEX::Enumeration::BlockCiphers::AHX:
		case CEX::Enumeration::BlockCiphers::RHX:
		{
#if defined(AESNI_AVAILABLE)
			CEX::Common::CpuDetect detect;
			if (detect.AES)
				return new CEX::Cipher::Symmetric::Block::AHX(RoundCount, KdfEngineType);
			else
				return new CEX::Cipher::Symmetric::Block::RHX(BlockSize, RoundCount, KdfEngineType);
#else
			return new CEX::Cipher::Symmetric::Block::RHX(BlockSize, RoundCount, KdfEngineType);
#endif
		}
		case CEX::Enumeration::BlockCiphers::SHX:
			return new CEX::Cipher::Symmetric::Block::SHX(RoundCount, KdfEngineType);
		case CEX::Enumeration::BlockCiphers::THX:
			return new CEX::Cipher::Symmetric::Block::THX(RoundCount, KdfEngineType);
		default:
#if defined(ENABLE_CPPEXCEPTIONS)
			throw CEX::Exception::CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
#else
			return 0;
#endif
	}
}

NAMESPACE_HELPEREND