#include "BlockCipherFromName.h"
#include "RHX.h"
#include "SHX.h"
#include "THX.h"

NAMESPACE_HELPER

CEX::Cipher::Symmetric::Block::IBlockCipher* BlockCipherFromName::GetInstance(CEX::Enumeration::BlockCiphers BlockCipherType)
{
	switch (BlockCipherType)
	{
		case CEX::Enumeration::BlockCiphers::RHX:
			return new CEX::Cipher::Symmetric::Block::RHX();
		case CEX::Enumeration::BlockCiphers::SHX:
			return new CEX::Cipher::Symmetric::Block::SHX();
		case CEX::Enumeration::BlockCiphers::THX:
			return new CEX::Cipher::Symmetric::Block::THX();
		default:
			throw CEX::Exception::CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
	}
}

CEX::Cipher::Symmetric::Block::IBlockCipher* BlockCipherFromName::GetInstance(CEX::Enumeration::BlockCiphers BlockCipherType, uint BlockSize, uint RoundCount, CEX::Enumeration::Digests KdfEngineType)
{
	switch (BlockCipherType)
	{
		case CEX::Enumeration::BlockCiphers::RHX:
			return new CEX::Cipher::Symmetric::Block::RHX(BlockSize, RoundCount, KdfEngineType);
		case CEX::Enumeration::BlockCiphers::SHX:
			return new CEX::Cipher::Symmetric::Block::SHX(RoundCount, KdfEngineType);
		case CEX::Enumeration::BlockCiphers::THX:
			return new CEX::Cipher::Symmetric::Block::THX(RoundCount, KdfEngineType);
		default:
			throw CEX::Exception::CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
	}
}

NAMESPACE_HELPEREND