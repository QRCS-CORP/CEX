#include "DigestFromName.h"
#include "BlakeB512.h"
#include "BlakeS256.h"
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
		case Digests::BlakeB512:
			return new Digest::BlakeB512(Parallel);
		case Digests::BlakeBP512:
			return new Digest::BlakeB512(true);
		case Digests::BlakeS256:
			return new Digest::BlakeS256(Parallel);
		case Digests::BlakeSP256:
			return new Digest::BlakeS256(true);
		case Digests::Keccak256:
			return new Digest::Keccak256();
		case Digests::Keccak512:
			return new Digest::Keccak512();
		case Digests::SHA256:
			return new Digest::SHA256(Parallel);
		case Digests::SHA512:
			return new Digest::SHA512(Parallel);
		case Digests::Skein256:
			return new Digest::Skein256();
		case Digests::Skein512:
			return new Digest::Skein512();
		case Digests::Skein1024:
			return new Digest::Skein1024();
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
		case Digests::BlakeS256:
		case Digests::SHA256:
		case Digests::Skein512:
			return 64;
		case Digests::BlakeB512:
		case Digests::SHA512:
		case Digests::Skein1024:
			return 128;
		case Digests::Keccak256:
			return 136;
		case Digests::Keccak512:
			return 72;
		case Digests::BlakeSP256:
		case Digests::BlakeBP512:
			return 16384;

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
		case Digests::BlakeS256:
		case Digests::BlakeSP256:
		case Digests::Keccak256:
		case Digests::SHA256:
		case Digests::Skein256:
			return 32;
		case Digests::BlakeB512:
		case Digests::BlakeBP512:
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
		case Digests::BlakeS256:
		case Digests::BlakeSP256:
		case Digests::BlakeB512:
		case Digests::BlakeBP512:
		case Digests::Skein256:
		case Digests::Skein512:
		case Digests::Skein1024:
			return 0;
		case Digests::Keccak256:
		case Digests::Keccak512:
			return 1;
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