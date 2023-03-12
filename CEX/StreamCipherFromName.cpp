#include "StreamCipherFromName.h"
#include "CpuDetect.h"
#include "ChaChaP20.h"
#include "CSX512.h"
#include "CryptoSymmetricException.h"
#include "RCS.h"
#include "RWS.h"
#include "TSX256.h"
#include "TSX512.h"
#include "TSX1024.h"

NAMESPACE_HELPER

using namespace Cipher::Stream;
using Exception::CryptoSymmetricException;
using Enumeration::ErrorCodes;
using Enumeration::KmacModes;
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
			case StreamCiphers::ChaChaP20:
			{
				cptr = new ChaChaP20(false);
				break;
			}
			case StreamCiphers::CSXR20K256:
			{
				cptr = new ChaChaP20(true);
				break;
			}
			case StreamCiphers::CSX512:
			{
				cptr = new ChaChaP20(false);
				break;
			}
			case StreamCiphers::CSXR80K512:
			{
				cptr = new ChaChaP20(true);
				break;
			}
			case StreamCiphers::RCS:
			{
				cptr = new RCS(false);
				break;
			}
			case StreamCiphers::RCSK256:
			case StreamCiphers::RCSK512:
			case StreamCiphers::RCSK1024:
			{
				cptr = new RCS(true);
				break;
			}
			case StreamCiphers::RWS:
			{
				cptr = new RWS(false);
				break;
			}
			case StreamCiphers::RWSK256:
			case StreamCiphers::RWSK512:
			case StreamCiphers::RWSK1024:
			{
				cptr = new RWS(true);
				break;
			}
			case StreamCiphers::TSX256:
			{
				cptr = new TSX256(false);
				break;
			}
			case StreamCiphers::TSXR72K256:
			{
				cptr = new TSX256(true);
				break;
			}
			case StreamCiphers::TSX512:
			{
				cptr = new TSX512(false);
				break;
			}
			case StreamCiphers::TSXR96K512:
			{
				cptr = new TSX512(true);
				break;
			}
			case StreamCiphers::TSX1024:
			{
				cptr = new TSX1024(false);
				break;
			}
			case StreamCiphers::TSXR120K512:
			{
				cptr = new TSX1024(true);
				break;
			}
			default:
			{
				// invalid parameter
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
