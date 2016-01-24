#include "DigestFromName.h"
#include "Blake256.h"
#include "Blake512.h"
#include "Keccak256.h"
#include "Keccak512.h"
#include "SHA256.h"
#include "SHA512.h"
#include "Skein256.h"
#include "Skein512.h"
#include "Skein1024.h"

NAMESPACE_HELPER

using namespace CEX::Digest;

IDigest* DigestFromName::GetInstance(Digests DigestType)
{
	switch (DigestType)
	{
		case Digests::Blake256:
			return new Blake256();
		case Digests::Blake512:
			return new Blake512();
		case Digests::Keccak256:
			return new Keccak256();
		case Digests::Keccak512:
			return new Keccak512();
		case Digests::SHA256:
			return new SHA256();
		case Digests::SHA512:
			return new SHA512();
		case Digests::Skein256:
			return new Skein256();
		case Digests::Skein512:
			return new Skein512();
		case Digests::Skein1024:
			return new Skein1024();
		default:
			throw CryptoException("DigestFromName:GetInstance", "The digest is not recognized!");
	}
}

NAMESPACE_HELPEREND