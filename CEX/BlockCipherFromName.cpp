#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "AHX.h"
#include "RHX.h"
#include "SHX.h"
#include "THX.h"

NAMESPACE_HELPER

IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers BlockCipherType, Digests KdfEngineType)
{
	try
	{ 
		Common::CpuDetect detect;

		switch (BlockCipherType)
		{
		case BlockCiphers::AHX:
		{
			if (detect.AESNI())
				return new Cipher::Symmetric::Block::AHX(KdfEngineType, 22);
			else
				return new Cipher::Symmetric::Block::RHX(KdfEngineType, 22);
		}
		case BlockCiphers::Rijndael:
		{
			if (detect.AESNI())
				return new Cipher::Symmetric::Block::AHX();
			else
				return new Cipher::Symmetric::Block::RHX();
		}
		case BlockCiphers::RHX:
			return new Cipher::Symmetric::Block::RHX(KdfEngineType, 22);
		case BlockCiphers::Serpent:
			return new Cipher::Symmetric::Block::SHX();
		case BlockCiphers::SHX:
			return new Cipher::Symmetric::Block::SHX(KdfEngineType, 40);
		case BlockCiphers::Twofish:
			return new Cipher::Symmetric::Block::THX();
		case BlockCiphers::THX:
			return new Cipher::Symmetric::Block::THX(KdfEngineType, 20);

		default:
			throw Exception::CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("BlockCipherFromName:GetInstance", "The specified block cipher type is unavailable!", std::string(ex.what()));
	}
}

IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers BlockCipherType, uint BlockSize, uint RoundCount, Digests KdfEngineType)
{
	try
	{
		Common::CpuDetect detect;

		switch (BlockCipherType)
		{
			case BlockCiphers::AHX:
			{
				if (detect.AESNI())
					return new Cipher::Symmetric::Block::AHX(KdfEngineType, RoundCount);
				else
					return new Cipher::Symmetric::Block::RHX(KdfEngineType, BlockSize, RoundCount);
			}
			case BlockCiphers::Rijndael:
			{
				if (detect.AESNI())
					return new Cipher::Symmetric::Block::AHX();
				else
					return new Cipher::Symmetric::Block::RHX();
			}
			case BlockCiphers::RHX:
				return new Cipher::Symmetric::Block::RHX(KdfEngineType, RoundCount, 16);
			case BlockCiphers::Serpent:
				return new Cipher::Symmetric::Block::SHX();
			case BlockCiphers::SHX:
				return new Cipher::Symmetric::Block::SHX(KdfEngineType, RoundCount);
			case BlockCiphers::Twofish:
				return new Cipher::Symmetric::Block::THX();
			case BlockCiphers::THX:
				return new Cipher::Symmetric::Block::THX(KdfEngineType, RoundCount);

			default:
				throw Exception::CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("BlockCipherFromName:GetInstance", "The specified block cipher type is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND