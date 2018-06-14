#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#if defined(__AVX__)
#	include "AHX.h"
#endif
#include "RHX.h"
#include "SHX.h"
#include "THX.h"

NAMESPACE_HELPER

IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers CipherType, BlockCipherExtensions CipherExtension)
{
	IBlockCipher* cprPtr = nullptr;

	try
	{ 
		Common::CpuDetect detect;

		switch (CipherType)
		{
			case BlockCiphers::AHX:
			{
	#if defined(__AVX__)
				if (detect.AESNI())
				{
					cprPtr = new Cipher::Symmetric::Block::AHX(CipherExtension);
				}
				else
	#endif
				{
					cprPtr = new Cipher::Symmetric::Block::RHX(CipherExtension);
				}
				break;
			}
			case BlockCiphers::Rijndael:
			{
	#if defined(__AVX__)
				if (detect.AESNI())
				{
					cprPtr = new Cipher::Symmetric::Block::AHX();
				}
				else
	#endif
				{
					cprPtr = new Cipher::Symmetric::Block::RHX();
				}
				break;
			}
			case BlockCiphers::RHX:
			{
				cprPtr = new Cipher::Symmetric::Block::RHX(CipherExtension);
				break;
			}
			case BlockCiphers::Serpent:
			{
				cprPtr = new Cipher::Symmetric::Block::SHX();
				break;
			}
			case BlockCiphers::SHX:
			{
				cprPtr = new Cipher::Symmetric::Block::SHX(CipherExtension);
				break;
			}
			case BlockCiphers::Twofish:
			{
				cprPtr = new Cipher::Symmetric::Block::THX();
				break;
			}
			case BlockCiphers::THX:
			{
				cprPtr = new Cipher::Symmetric::Block::THX(CipherExtension);
				break;
			}
			default:
			{
				throw CryptoException("BlockCipherFromName:GetInstance", "The cipher engine is not supported!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("BlockCipherFromName:GetInstance", "The specified block cipher type is unavailable!", std::string(ex.what()));
	}

	return cprPtr;
}

NAMESPACE_HELPEREND
