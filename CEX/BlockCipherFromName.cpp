#include "BlockCipherFromName.h"
#include "CryptoSymmetricException.h"
#include "RHX.h"
#include "SHX.h"

NAMESPACE_HELPER

using Exception::CryptoSymmetricException;
using Enumeration::ErrorCodes;

const std::string BlockCipherFromName::CLASS_NAME("BlockCipherFromName");

IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers CipherType)
{
	using namespace Cipher::Block;

	IBlockCipher* cptr;

	cptr = nullptr;

	try
	{ 
		switch (CipherType)
		{
			case BlockCiphers::AES:
			{
				cptr = new RHX(BlockCipherExtensions::None);
				break;
			}
			case BlockCiphers::RHXH256:
			{
				cptr = new RHX(BlockCipherExtensions::HKDF256);
				break;
			}
			case BlockCiphers::RHXH512:
			{
				cptr = new RHX(BlockCipherExtensions::HKDF512);
				break;
			}
			case BlockCiphers::RHXS256:
			{
				cptr = new RHX(BlockCipherExtensions::SHAKE256);
				break;
			}
			case BlockCiphers::RHXS512:
			{
				cptr = new RHX(BlockCipherExtensions::SHAKE512);
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
			default:
			{
				// invalid parameter
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The cipher engine is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoSymmetricException &ex)
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
