#include "DigestFromName.h"
#include "Blake512.h"
#include "Blake256.h"
#include "CryptoDigestException.h"
#include "Keccak256.h"
#include "Keccak512.h"
#include "Keccak1024.h"
#include "SHA256.h"
#include "SHA512.h"
#include "Skein256.h"
#include "Skein512.h"
#include "Skein1024.h"

NAMESPACE_HELPER

using Exception::CryptoDigestException;
using Enumeration::ErrorCodes;

const std::string DigestFromName::CLASS_NAME("DigestFromName");

IDigest* DigestFromName::GetInstance(Digests DigestType, bool Parallel)
{
	using namespace Digest;

	IDigest* dptr;

	dptr = nullptr;

	try
	{
		switch (DigestType)
		{
			case Digests::Blake256:
			{
				dptr = new Blake256(Parallel);
				break;
			}
			case Digests::Blake512:
			{
				dptr = new Blake512(Parallel);
				break;
			}
			case Digests::Keccak256:
			{
				dptr = new Keccak256(Parallel);
				break;
			}
			case Digests::Keccak512:
			{
				dptr = new Keccak512(Parallel);
				break;
			}
			case Digests::Keccak1024:
			{
				dptr = new Keccak1024(Parallel);
				break;
			}
			case Digests::SHA256:
			{
				dptr = new SHA256(Parallel);
				break;
			}
			case Digests::SHA512:
			{
				dptr = new SHA512(Parallel);
				break;
			}
			case Digests::Skein256:
			{
				dptr = new Skein256(Parallel);
				break;
			}
			case Digests::Skein512:
			{
				dptr = new Skein512(Parallel);
				break;
			}
			case Digests::Skein1024:
			{
				dptr = new Skein1024(Parallel);
				break;
			}
			default:
			{
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoDigestException &ex)
	{
		throw CryptoException("DigestFromName:GetInstance", "The digest is unavailable!", ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("DigestFromName:GetInstance", "The digest has thrown an exception!", std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return dptr;
}

size_t DigestFromName::GetBlockSize(Digests DigestType)
{
	size_t blen;

	blen = 0;

	switch (DigestType)
	{
		case Digests::Skein256:
		{
			blen = 32;
			break;
		}
		case Digests::Blake256:
		case Digests::SHA256:
		case Digests::Skein512:
		{
			blen = 64;
			break;
		}
		case Digests::Blake512:
		case Digests::SHA512:
		case Digests::Skein1024:
		{
			blen = 128;
			break;
		}
		case Digests::Keccak256:
		{
			blen = 136;
			break;
		}
		case Digests::Keccak512:
		case Digests::Keccak1024:
		{
			blen = 72;
			break;
		}
		case Digests::None:
		{
			blen = 0;
			break;
		}
		default:
		{
			throw CryptoException(CLASS_NAME, std::string("GetBlockSize"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam);
		}
	}

	return blen;
}

size_t DigestFromName::GetDigestSize(Digests DigestType)
{
	size_t dlen;

	dlen = 0;

	switch (DigestType)
	{
		case Digests::Blake256:
		case Digests::Keccak256:
		case Digests::SHA256:
		case Digests::Skein256:
		{
			dlen = 32;
			break;
		}
		case Digests::Blake512:
		case Digests::Keccak512:
		case Digests::SHA512:
		case Digests::Skein512:
		{
			dlen = 64;
			break;
		}
		case Digests::Keccak1024:
		case Digests::Skein1024:
		{
			dlen = 128;
			break;
		}
		case Digests::None:
		{
			dlen = 0;
			break;
		}
		default:
		{
			throw CryptoException(CLASS_NAME, std::string("GetDigestSize"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam);
		}
	}

	return dlen;
}

size_t DigestFromName::GetPaddingSize(Digests DigestType)
{
	size_t plen;

	plen = 0;

	switch (DigestType)
	{
		case Digests::Blake256:
		case Digests::Blake512:
		case Digests::Keccak256:
		case Digests::Keccak512:
		case Digests::Keccak1024:
		case Digests::Skein256:
		case Digests::Skein512:
		case Digests::Skein1024:
		{
			plen = 0;
			break;
		}
		case Digests::SHA256:
		{
			plen = 9;
			break;
		}
		case Digests::SHA512:
		{
			plen = 17;
			break;
		}
		case Digests::None:
		{
			plen = 0;
			break;
		}
		default:
		{
			throw CryptoException(CLASS_NAME, std::string("GetPaddingSize"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam);
		}
	}

	return plen;
}

NAMESPACE_HELPEREND