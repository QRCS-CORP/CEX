#include "DigestFromName.h"
#include "Blake512.h"
#include "Blake256.h"
#include "Keccak256.h"
#include "Keccak512.h"
#include "Keccak1024.h"
#include "SHA256.h"
#include "SHA512.h"
#include "Skein256.h"
#include "Skein512.h"
#include "Skein1024.h"

NAMESPACE_HELPER

IDigest* DigestFromName::GetInstance(Digests DigestType, bool Parallel)
{
	IDigest* dgtPtr;

	try
	{
		switch (DigestType)
		{
			case Digests::Blake256:
			{
				dgtPtr = new Digest::Blake256(Parallel);
				break;
			}
			case Digests::Blake512:
			{
				dgtPtr = new Digest::Blake512(Parallel);
				break;
			}
			case Digests::Keccak256:
			{
				dgtPtr = new Digest::Keccak256(Parallel);
				break;
			}
			case Digests::Keccak512:
			{
				dgtPtr = new Digest::Keccak512(Parallel);
				break;
			}
			case Digests::Keccak1024:
			{
				dgtPtr = new Digest::Keccak1024(Parallel);
				break;
			}
			case Digests::SHA256:
			{
				dgtPtr = new Digest::SHA256(Parallel);
				break;
			}
			case Digests::SHA512:
			{
				dgtPtr = new Digest::SHA512(Parallel);
				break;
			}
			case Digests::Skein256:
			{
				dgtPtr = new Digest::Skein256(Parallel);
				break;
			}
			case Digests::Skein512:
			{
				dgtPtr = new Digest::Skein512(Parallel);
				break;
			}
			case Digests::Skein1024:
			{
				dgtPtr = new Digest::Skein1024(Parallel);
				break;
			}
			default:
			{
				throw CryptoException("DigestFromName:GetInstance", "The digest is not recognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("DigestFromName:GetInstance", "The digest is unavailable!", std::string(ex.what()));
	}

	return dgtPtr;
}

size_t DigestFromName::GetBlockSize(Digests DigestType)
{
	size_t blkSize = 0;

	switch (DigestType)
	{
		case Digests::Skein256:
		{
			blkSize = 32;
			break;
		}
		case Digests::Blake256:
		case Digests::SHA256:
		case Digests::Skein512:
		{
			blkSize = 64;
			break;
		}
		case Digests::Blake512:
		case Digests::SHA512:
		case Digests::Skein1024:
		{
			blkSize = 128;
			break;
		}
		case Digests::Keccak256:
		{
			blkSize = 136;
			break;
		}
		case Digests::Keccak512:
		case Digests::Keccak1024:
		{
			blkSize = 72;
			break;
		}
		case Digests::None:
		{
			blkSize = 0;
			break;
		}
		default:
		{
			throw CryptoException("DigestFromName:GetBlockSize", "The digest type is not supported!");
		}
	}

	return blkSize;
}

size_t DigestFromName::GetDigestSize(Digests DigestType)
{
	size_t dgtSize = 0;

	switch (DigestType)
	{
		case Digests::Blake256:
		case Digests::Keccak256:
		case Digests::SHA256:
		case Digests::Skein256:
		{
			dgtSize = 32;
			break;
		}
		case Digests::Blake512:
		case Digests::Keccak512:
		case Digests::SHA512:
		case Digests::Skein512:
		{
			dgtSize = 64;
			break;
		}
		case Digests::Keccak1024:
		case Digests::Skein1024:
		{
			dgtSize = 128;
			break;
		}
		case Digests::None:
		{
			dgtSize = 0;
			break;
		}
		default:
		{
			throw CryptoException("DigestFromName:GetDigestSize", "The digest type is not supported!");
		}
	}

	return dgtSize;
}

size_t DigestFromName::GetPaddingSize(Digests DigestType)
{
	size_t padSize = 0;

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
			padSize = 0;
			break;
		}
		case Digests::SHA256:
		{
			padSize = 9;
			break;
		}
		case Digests::SHA512:
		{
			padSize = 17;
			break;
		}
		case Digests::None:
		{
			padSize = 0;
			break;
		}
		default:
		{
			throw CryptoException("DigestFromName:GetPaddingSize", "The digest type is not supported!");
		}
	}

	return padSize;
}

NAMESPACE_HELPEREND
