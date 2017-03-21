#include "DigestFromName.h"
#include "Blake512.h"
#include "Blake256.h"
#include "Keccak256.h"
#include "Keccak512.h"
#include "SHA256.h"
#include "SHA512.h"
#include "Skein256.h"
#include "Skein512.h"
#include "Skein1024.h"

NAMESPACE_HELPER

IDigest* DigestFromName::GetInstance(Digests DigestType, bool Parallel)
{
	try
	{
		switch (DigestType)
		{
		case Digests::Blake512:
			return new Digest::Blake512(Parallel);
		case Digests::Blake256:
			return new Digest::Blake256(Parallel);
		case Digests::Keccak256:
			return new Digest::Keccak256();
		case Digests::Keccak512:
			return new Digest::Keccak512();
		case Digests::SHA256:
			return new Digest::SHA256(Parallel);
		case Digests::SHA512:
			return new Digest::SHA512(Parallel);
		case Digests::Skein256:
			return new Digest::Skein256(Parallel);
		case Digests::Skein512:
			return new Digest::Skein512(Parallel);
		case Digests::Skein1024:
			return new Digest::Skein1024(Parallel);
		default:
			throw Exception::CryptoException("DigestFromName:GetInstance", "The digest is not recognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("DigestFromName:GetInstance", "The digest is unavailable!", std::string(ex.what()));
	}
}

size_t DigestFromName::GetBlockSize(Digests DigestType)
{
	try
	{
		switch (DigestType)
		{
		case Digests::Skein256:
			return 32;
		case Digests::Blake256:
		case Digests::SHA256:
		case Digests::Skein512:
			return 64;
		case Digests::Blake512:
		case Digests::SHA512:
		case Digests::Skein1024:
			return 128;
		case Digests::Keccak256:
			return 136;
		case Digests::Keccak512:
			return 72;

		case Digests::None:
			return 0;
		default:
			throw Exception::CryptoException("DigestFromName:GetBlockSize", "The digest type is not supported!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("DigestFromName:GetBlockSize", "The digest is unavailable!", std::string(ex.what()));
	}
}

size_t DigestFromName::GetDigestSize(Digests DigestType)
{
	try
	{
		switch (DigestType)
		{
		case Digests::Blake256:
		case Digests::Keccak256:
		case Digests::SHA256:
		case Digests::Skein256:
			return 32;
		case Digests::Blake512:
		case Digests::Keccak512:
		case Digests::SHA512:
		case Digests::Skein512:
			return 64;
		case Digests::Skein1024:
			return 128;
		case Digests::None:
			return 0;
		default:
			throw Exception::CryptoException("DigestFromName:GetDigestSize", "The digest type is not supported!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("DigestFromName:GetDigestSize", "The digest is unavailable!", std::string(ex.what()));
	}
}

size_t DigestFromName::GetPaddingSize(Digests DigestType)
{
	try
	{
		switch (DigestType)
		{
		case Digests::Blake256:
		case Digests::Blake512:
		case Digests::Keccak256:
		case Digests::Keccak512:
		case Digests::Skein256:
		case Digests::Skein512:
		case Digests::Skein1024:
			return 0;
		case Digests::SHA256:
			return 9;
		case Digests::SHA512:
			return 17;
		case Digests::None:
			return 0;
		default:
			throw Exception::CryptoException("DigestFromName:GetPaddingSize", "The digest type is not supported!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("DigestFromName:GetPaddingSize", "The digest is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND