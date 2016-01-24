#include "BlockCipherFromName.h"
#include "RHX.h"
#include "SHX.h"
#include "THX.h"

NAMESPACE_HELPER

using namespace CEX::Cipher::Symmetric::Block;

IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers EngineType)
{
	switch (EngineType)
	{
		case BlockCiphers::RHX:
			return new RHX();
		case BlockCiphers::SHX:
			return new SHX();
		case BlockCiphers::THX:
			return new THX();
		default:
			throw CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
	}
}

IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine)
{
	switch (EngineType)
	{
		case BlockCiphers::RHX:
			return new RHX(BlockSize, RoundCount, KdfEngine);
		case BlockCiphers::SHX:
			return new SHX(RoundCount, KdfEngine);
		case BlockCiphers::THX:
			return new THX(RoundCount, KdfEngine);
		default:
			throw CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
	}
}

NAMESPACE_HELPEREND