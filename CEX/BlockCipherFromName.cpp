#include "BlockCipherFromName.h"
#include "CpuDetect.h"
#include "CryptoSymmetricCipherException.h"
#if defined(__AVX__)
#	include "AHX.h"
#endif
#include "RHX.h"
#include "SHX.h"

NAMESPACE_HELPER

using Exception::CryptoSymmetricCipherException;
using Enumeration::ErrorCodes;

const std::string BlockCipherFromName::CLASS_NAME("BlockCipherFromName");

IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers CipherType)
{
	using namespace Cipher::Block;

	IBlockCipher* cptr;

	cptr = nullptr;

	try
	{ 
		CpuDetect detect;

		switch (CipherType)
		{
			case BlockCiphers::AES:
			{
	#if defined(__AVX__)
				if (detect.AESNI())
				{
					cptr = new AHX(BlockCipherExtensions::None);
				}
				else
	#endif
				{
					cptr = new RHX(BlockCipherExtensions::None);
				}
				break;
			}
			case BlockCiphers::RHXH256:
			{
	#if defined(__AVX__)
				if (detect.AESNI())
				{
					cptr = new AHX(BlockCipherExtensions::HKDF256);
				}
				else
	#endif
				{
					cptr = new RHX(BlockCipherExtensions::HKDF256);
				}
				break;
			}
			case BlockCiphers::RHXH512:
			{
#if defined(__AVX__)
				if (detect.AESNI())
				{
					cptr = new AHX(BlockCipherExtensions::HKDF512);
				}
				else
#endif
				{
					cptr = new RHX(BlockCipherExtensions::HKDF512);
				}
				break;
			}
			case BlockCiphers::RHXS256:
			{
#if defined(__AVX__)
				if (detect.AESNI())
				{
					cptr = new AHX(BlockCipherExtensions::SHAKE256);
				}
				else
#endif
				{
					cptr = new RHX(BlockCipherExtensions::SHAKE256);
				}
				break;
			}
			case BlockCiphers::RHXS512:
			{
#if defined(__AVX__)
				if (detect.AESNI())
				{
					cptr = new AHX(BlockCipherExtensions::SHAKE512);
				}
				else
#endif
				{
					cptr = new RHX(BlockCipherExtensions::SHAKE512);
				}
				break;
			}
			case BlockCiphers::RHXS1024:
			{
#if defined(__AVX__)
				if (detect.AESNI())
				{
					cptr = new AHX(BlockCipherExtensions::SHAKE1024);
				}
				else
#endif
				{
					cptr = new RHX(BlockCipherExtensions::SHAKE1024);
				}
				break;
			}
			case BlockCiphers::Serpent:
			{
				cptr = new SHX(BlockCipherExtensions::None);
				break;
			}
			case BlockCiphers::SHXH256:
			{
				cptr = new SHX(BlockCipherExtensions::HKDF256);
				break;
			}
			case BlockCiphers::SHXH512:
			{
				cptr = new SHX(BlockCipherExtensions::HKDF512);
				break;
			}
			case BlockCiphers::SHXS256:
			{
				cptr = new SHX(BlockCipherExtensions::SHAKE256);
				break;
			}
			case BlockCiphers::SHXS512:
			{
				cptr = new SHX(BlockCipherExtensions::SHAKE512);
				break;
			}
			case BlockCiphers::SHXS1024:
			{
				cptr = new SHX(BlockCipherExtensions::SHAKE1024);
				break;
			}
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The cipher engine is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoSymmetricCipherException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return cptr;
}

NAMESPACE_HELPEREND
