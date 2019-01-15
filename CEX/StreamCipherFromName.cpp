#include "StreamCipherFromName.h"
#include "ACS.h"
#include "ChaCha256.h"
#include "ChaCha512.h"
#include "CryptoSymmetricCipherException.h"
#include "Threefish256.h"
#include "Threefish512.h"
#include "Threefish1024.h"

NAMESPACE_HELPER

using Exception::CryptoSymmetricCipherException;
using Enumeration::ErrorCodes;

IStreamCipher* StreamCipherFromName::GetInstance(StreamCiphers StreamCipherType)
{
	IStreamCipher* cptr;

	cptr = nullptr;

	try
	{
		switch (StreamCipherType)
		{
			case StreamCiphers::ACS:
			case StreamCiphers::ACS512A:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::AHX, Enumeration::BlockCipherExtensions::SHAKE512, Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::ACS256A:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::AHX, Enumeration::BlockCipherExtensions::SHAKE256, Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::ACS256S:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::SHX, Enumeration::BlockCipherExtensions::SHAKE256, Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::ACS512S:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::SHX, Enumeration::BlockCipherExtensions::SHAKE512, Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::ChaCha256:
			{
				cptr = new Cipher::Stream::ChaCha256(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::ChaCha256AE:
			{
				cptr = new Cipher::Stream::ChaCha256(Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::ChaCha512:
			{
				cptr = new Cipher::Stream::ChaCha512(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::ChaCha512AE:
			{
				cptr = new Cipher::Stream::ChaCha512(Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::Threefish256:
			{
				cptr = new Cipher::Stream::Threefish256(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::Threefish256AE:
			{
				cptr = new Cipher::Stream::Threefish256(Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::Threefish512:
			{
				cptr = new Cipher::Stream::Threefish512(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::Threefish512AE:
			{
				cptr = new Cipher::Stream::Threefish512(Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::Threefish1024:
			{
				cptr = new Cipher::Stream::Threefish1024(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::Threefish1024AE:
			{
				cptr = new Cipher::Stream::Threefish1024(Enumeration::StreamAuthenticators::KMAC1024);
				break;
			}
			default:
			{
				throw CryptoException(std::string("StreamCipherFromName"), std::string("GetInstance"), std::string("The stream cipher type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoSymmetricCipherException &ex)
	{
		throw CryptoException(std::string("StreamCipherFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("StreamCipherFromName"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return cptr;
}

NAMESPACE_HELPEREND
