#include "StreamCipherFromName.h"
#include "ACS.h"
#include "CpuDetect.h"
#include "CSX256.h"
#include "CSX512.h"
#include "CryptoSymmetricException.h"
#include "MCS.h"
#include "RCS.h"
#include "TSX256.h"
#include "TSX512.h"
#include "TSX1024.h"

NAMESPACE_HELPER

using namespace Cipher::Stream;
using Enumeration::BlockCiphers;
using Exception::CryptoSymmetricException;
using Enumeration::ErrorCodes;
using Enumeration::StreamAuthenticators;

const std::string StreamCipherFromName::CLASS_NAME("StreamCipherFromName");

IStreamCipher* StreamCipherFromName::GetInstance(StreamCiphers StreamCipherType)
{
	IStreamCipher* cptr;
	CpuDetect dtc;

	cptr = nullptr;

	try
	{
		switch (StreamCipherType)
		{
			case StreamCiphers::CSX256:
			{
				cptr = new CSX256(StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::CSXR20H256:
			{
				cptr = new CSX256(StreamAuthenticators::HMACSHA256);
				break;
			}
			case StreamCiphers::CSXR20H512:
			{
				cptr = new CSX256(StreamAuthenticators::HMACSHA512);
				break;
			}
			case StreamCiphers::CSXR20K256:
			{
				cptr = new CSX256(StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::CSXR20K512:
			{
				cptr = new CSX256(StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::CSXR20P256:
			{
				cptr = new CSX256(StreamAuthenticators::Poly1305);
				break;
			}
			case StreamCiphers::CSX512:
			{
				cptr = new CSX256(StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::CSXR80H256:
			{
				cptr = new CSX256(StreamAuthenticators::HMACSHA256);
				break;
			}
			case StreamCiphers::CSXR80H512:
			{
				cptr = new CSX256(StreamAuthenticators::HMACSHA512);
				break;
			}
			case StreamCiphers::CSXR80K256:
			{
				cptr = new CSX256(StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::CSXR80K512:
			{
				cptr = new CSX256(StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::CSXR80P256:
			{
				cptr = new CSX256(StreamAuthenticators::Poly1305);
				break;
			}
			case StreamCiphers::MCSRH256:
			{
				cptr = new MCS(BlockCiphers::AES, StreamAuthenticators::HMACSHA256);
				break;
			}
			case StreamCiphers::MCSRH512:
			{
				cptr = new MCS(BlockCiphers::AES, StreamAuthenticators::HMACSHA512);
				break;
			}
			case StreamCiphers::MCSRK256:
			{
				cptr = new MCS(BlockCiphers::AES, StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::MCSRK512:
			{
				cptr = new MCS(BlockCiphers::AES, StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::MCSRP256:
			{
				cptr = new MCS(BlockCiphers::AES, StreamAuthenticators::Poly1305);
				break;
			}
			case StreamCiphers::MCSSH256:
			{
				cptr = new MCS(BlockCiphers::Serpent, StreamAuthenticators::HMACSHA256);
				break;
			}
			case StreamCiphers::MCSSH512:
			{
				cptr = new MCS(BlockCiphers::Serpent, StreamAuthenticators::HMACSHA512);
				break;
			}
			case StreamCiphers::MCSSK256:
			{
				cptr = new MCS(BlockCiphers::Serpent, StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::MCSSK512:
			{
				cptr = new MCS(BlockCiphers::Serpent, StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::MCSSP256:
			{
				cptr = new MCS(BlockCiphers::Serpent, StreamAuthenticators::Poly1305);
				break;
			}
			case StreamCiphers::MCSR:
			{
				cptr = new MCS(BlockCiphers::AES, StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::RCS:
			{
#if defined(__AVX__)
				if (dtc.AESNI())
				{
					cptr = new ACS(StreamAuthenticators::None);
				}
				else
#endif
				{
					cptr = new RCS(StreamAuthenticators::None);
				}
				break;
			}
			case StreamCiphers::RCSH256:
			{
#if defined(__AVX__)
				if (dtc.AESNI())
				{
					cptr = new ACS(StreamAuthenticators::HMACSHA256);
				}
				else
#endif
				{
					cptr = new RCS(StreamAuthenticators::HMACSHA256);
				}
				break;
			}
			case StreamCiphers::RCSH512:
			{
#if defined(__AVX__)
				if (dtc.AESNI())
				{
					cptr = new ACS(StreamAuthenticators::HMACSHA512);
				}
				else
#endif
				{
					cptr = new RCS(StreamAuthenticators::HMACSHA512);
				}
				break;
			}
			case StreamCiphers::RCSK256:
			{
#if defined(__AVX__)
				if (dtc.AESNI())
				{
					cptr = new ACS(StreamAuthenticators::KMAC256);
				}
				else
#endif
				{
					cptr = new RCS(StreamAuthenticators::KMAC256);
				}
				break;
			}
			case StreamCiphers::RCSK512:
			{
#if defined(__AVX__)
				if (dtc.AESNI())
				{
					cptr = new ACS(StreamAuthenticators::KMAC512);
				}
				else
#endif
				{
					cptr = new RCS(StreamAuthenticators::KMAC512);
				}
				break;
			}
			case StreamCiphers::RCSK1024:
			{
#if defined(__AVX__)
				if (dtc.AESNI())
				{
					cptr = new ACS(StreamAuthenticators::KMAC1024);
				}
				else
#endif
				{
					cptr = new RCS(StreamAuthenticators::KMAC1024);
				}
				break;
			}
			case StreamCiphers::RCSP256:
			{
#if defined(__AVX__)
				if (dtc.AESNI())
				{
					cptr = new ACS(StreamAuthenticators::Poly1305);
				}
				else
#endif
				{
					cptr = new RCS(StreamAuthenticators::Poly1305);
				}
				break;
			}
			case StreamCiphers::TSX256:
			{
				cptr = new TSX256(StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::TSXR72H256:
			{
				cptr = new TSX256(StreamAuthenticators::HMACSHA256);
				break;
			}
			case StreamCiphers::TSXR72H512:
			{
				cptr = new TSX256(StreamAuthenticators::HMACSHA512);
				break;
			}
			case StreamCiphers::TSXR72K256:
			{
				cptr = new TSX256(StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::TSXR72K512:
			{
				cptr = new TSX256(StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::TSXR72P256:
			{
				cptr = new TSX256(StreamAuthenticators::Poly1305);
				break;
			}
			case StreamCiphers::TSX512:
			{
				cptr = new TSX512(StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::TSXR96H256:
			{
				cptr = new TSX512(StreamAuthenticators::HMACSHA256);
				break;
			}
			case StreamCiphers::TSXR96H512:
			{
				cptr = new TSX512(StreamAuthenticators::HMACSHA512);
				break;
			}
			case StreamCiphers::TSXR96K256:
			{
				cptr = new TSX512(StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::TSXR96K512:
			{
				cptr = new TSX512(StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::TSXR96P256:
			{
				cptr = new TSX512(StreamAuthenticators::Poly1305);
				break;
			}
			case StreamCiphers::TSX1024:
			{
				cptr = new TSX1024(StreamAuthenticators::None);
				break;
			}
			case StreamCiphers::TSXR120H256:
			{
				cptr = new TSX1024(StreamAuthenticators::HMACSHA256);
				break;
			}
			case StreamCiphers::TSXR120H512:
			{
				cptr = new TSX1024(StreamAuthenticators::HMACSHA512);
				break;
			}
			case StreamCiphers::TSXR120K256:
			{
				cptr = new TSX1024(StreamAuthenticators::KMAC256);
				break;
			}
			case StreamCiphers::TSXR120K512:
			{
				cptr = new TSX1024(StreamAuthenticators::KMAC512);
				break;
			}
			case StreamCiphers::TSXR120K1024:
			{
				cptr = new TSX1024(StreamAuthenticators::KMAC1024);
				break;
			}
			case StreamCiphers::TSXR120P256:
			{
				cptr = new TSX1024(StreamAuthenticators::Poly1305);
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
