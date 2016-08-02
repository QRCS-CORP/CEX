#include "DigestFromName.h"
#include "Blake256.h"
#include "Blake512.h"
#include "Blake2Bp512.h"
#include "Blake2Sp256.h"
#include "Keccak256.h"
#include "Keccak512.h"
#include "SHA256.h"
#include "SHA512.h"
#include "Skein256.h"
#include "Skein512.h"
#include "Skein1024.h"

NAMESPACE_HELPER

CEX::Digest::IDigest* DigestFromName::GetInstance(CEX::Enumeration::Digests DigestType)
{
	switch (DigestType)
	{
	case CEX::Enumeration::Digests::Blake256:
		return new CEX::Digest::Blake256();
	case CEX::Enumeration::Digests::Blake512:
		return new CEX::Digest::Blake512();
	case CEX::Enumeration::Digests::Blake2B512:
		return new CEX::Digest::Blake2Bp512();
	case CEX::Enumeration::Digests::Blake2BP512:
		return new CEX::Digest::Blake2Bp512(true);
	case CEX::Enumeration::Digests::Blake2S256:
		return new CEX::Digest::Blake2Sp256();
	case CEX::Enumeration::Digests::Blake2SP256:
		return new CEX::Digest::Blake2Sp256(true);
	case CEX::Enumeration::Digests::Keccak256:
		return new CEX::Digest::Keccak256();
	case CEX::Enumeration::Digests::Keccak512:
		return new CEX::Digest::Keccak512();
	case CEX::Enumeration::Digests::SHA256:
		return new CEX::Digest::SHA256();
	case CEX::Enumeration::Digests::SHA512:
		return new CEX::Digest::SHA512();
	case CEX::Enumeration::Digests::Skein256:
		return new CEX::Digest::Skein256();
	case CEX::Enumeration::Digests::Skein512:
		return new CEX::Digest::Skein512();
	case CEX::Enumeration::Digests::Skein1024:
		return new CEX::Digest::Skein1024();
	default:
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CEX::Exception::CryptoException("DigestFromName:GetInstance", "The digest is not recognized!");
#else
		return 0;
#endif
	}
}

int DigestFromName::GetBlockSize(CEX::Enumeration::Digests DigestType)
{
	switch (DigestType)
	{
	case CEX::Enumeration::Digests::Skein256:
		return 32;
	case CEX::Enumeration::Digests::Blake256:
	case CEX::Enumeration::Digests::Blake2S256:
	case CEX::Enumeration::Digests::SHA256:
	case CEX::Enumeration::Digests::Skein512:
		return 64;
	case CEX::Enumeration::Digests::Blake512:
	case CEX::Enumeration::Digests::Blake2B512:
	case CEX::Enumeration::Digests::SHA512:
	case CEX::Enumeration::Digests::Skein1024:
		return 128;
	case CEX::Enumeration::Digests::Keccak256:
		return 136;
	case CEX::Enumeration::Digests::Keccak512:
		return 72;
	case CEX::Enumeration::Digests::Blake2SP256:
	case CEX::Enumeration::Digests::Blake2BP512:
		return 16384;

	case CEX::Enumeration::Digests::None:
		return 0;
	default:
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CEX::Exception::CryptoException("DigestFromName:GetBlockSize", "The digest type is not supported!");
#else
		return 0;
#endif
	}
}

int DigestFromName::GetDigestSize(CEX::Enumeration::Digests DigestType)
{
	switch (DigestType)
	{
	case CEX::Enumeration::Digests::Blake256:
	case CEX::Enumeration::Digests::Blake2S256:
	case CEX::Enumeration::Digests::Blake2SP256:
	case CEX::Enumeration::Digests::Keccak256:
	case CEX::Enumeration::Digests::SHA256:
	case CEX::Enumeration::Digests::Skein256:
		return 32;
	case CEX::Enumeration::Digests::Blake512:
	case CEX::Enumeration::Digests::Blake2B512:
	case CEX::Enumeration::Digests::Blake2BP512:
	case CEX::Enumeration::Digests::Keccak512:
	case CEX::Enumeration::Digests::SHA512:
	case CEX::Enumeration::Digests::Skein512:
		return 64;
	case CEX::Enumeration::Digests::Skein1024:
		return 128;
	case CEX::Enumeration::Digests::None:
		return 0;
	default:
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CEX::Exception::CryptoException("DigestFromName:GetDigestSize", "The digest type is not supported!");
#else
		return 0;
#endif

	}
}

NAMESPACE_HELPEREND