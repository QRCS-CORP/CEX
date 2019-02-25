#include "StreamCipherFromName.h"
#include "ACS.h"
#include "CSX256.h"
#include "CSX512.h"
#include "CryptoSymmetricException.h"
#include "TSX256.h"
#include "TSX512.h"
#include "TSX1024.h"

NAMESPACE_HELPER

using Exception::CryptoSymmetricException;
using Enumeration::ErrorCodes;

const std::string StreamCipherFromName::CLASS_NAME("StreamCipherFromName");

IStreamCipher* StreamCipherFromName::GetInstance(StreamCiphers StreamCipherType)
{
	IStreamCipher* cptr;

	cptr = nullptr;

	try
	{
		switch (StreamCipherType)
		{
			case StreamCiphers::ACS:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::ACS256H:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::RHXS256, Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::ACS512H:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::RHXS512, Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::ACS256S:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::SHXS256, Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::ACS512S:
			{
				cptr = new Cipher::Stream::ACS(Enumeration::BlockCiphers::SHXS512, Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::CSX256:
			{
				cptr = new Cipher::Stream::CSX256(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::CSX256AE:
			{
				cptr = new Cipher::Stream::CSX256(Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::CSX512:
			{
				cptr = new Cipher::Stream::CSX512(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::CSX512AE:
			{
				cptr = new Cipher::Stream::CSX512(Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::TSX256:
			{
				cptr = new Cipher::Stream::TSX256(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::TSX256AE:
			{
				cptr = new Cipher::Stream::TSX256(Enumeration::StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::TSX512:
			{
				cptr = new Cipher::Stream::TSX512(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::TSX512AE:
			{
				cptr = new Cipher::Stream::TSX512(Enumeration::StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::TSX1024:
			{
				cptr = new Cipher::Stream::TSX1024(Enumeration::StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::TSX1024AE:
			{
				cptr = new Cipher::Stream::TSX1024(Enumeration::StreamAuthenticators::KMAC1024);
				break;
			}
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The stream cipher type is not supported!"), ErrorCodes::InvalidParam);
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
