#include "ECDSABase.h"
#include "SHA2512.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_ECDSA

using Digest::SHA2512;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Asymmetric::Encrypt::ECDH::EC25519;

bool ECDSABase::Ed25519Sign(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<IDigest> &Digest)
{
	std::vector<uint8_t> az(64);
	std::vector<uint8_t> nonce(64);
	std::vector<uint8_t> hram(64);
	EC25519::ge25519p3 R = { 0 };

	// hash 1st half of sk to az
	Digest->Update(PrivateKey, 0, 32);
	Digest->Finalize(az, 0);
	// update with 2nd half of az
	Digest->Update(az, 32, 32);
	Digest->Update(Message, 0, Message.size());
	Digest->Finalize(nonce, 0);

	// move 2nd half of sk to 2nd half of sig
	MemoryTools::Copy(PrivateKey, 32, Signature, 32, 32);
	// reduce nonce
	EC25519::Sc25519Reduce(nonce);
	// scalar on nonce
	EC25519::Ge25519ScalarBase(R, nonce);
	// scalar to 1st half of sig
	EC25519::Ge25519P3ToBytes(Signature, R);

	// update hash with sig
	Digest->Update(Signature, 0, 64);
	// update hash with message
	Digest->Update(Message, 0, Message.size());
	// finalize to hram
	Digest->Finalize(hram, 0);

	// reduce hram
	EC25519::Sc25519Reduce(hram);
	// clamp az
	EC25519::Sc25519Clamp(az);
	// muladd hram, az, nonce to 2nd half of sig
	EC25519::Sc25519MulAdd(Signature, 32, hram, az, nonce);

	// cleanup
	MemoryTools::Clear(az, 0, az.size());
	MemoryTools::Clear(nonce, 0, nonce.size());

	return true;
}

bool ECDSABase::Ed25519Verify(const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PublicKey, std::unique_ptr<IDigest> &Digest)
{
	std::vector<uint8_t> h(64);
	std::vector<uint8_t> rcheck(32);
	EC25519::ge25519p3 A = { 0 };
	EC25519::ge25519p2 R = { 0 };
	bool res;

	res = true;

	if ((Signature[63] & 240) && EC25519::Sc25519IsCanonical(Signature, 32) == 0)
	{
		res = false;
	}
	else if (EC25519::Ge25519HasSmallOrder(Signature) != 0)
	{
		res = false;
	}
	else if (EC25519::Ge25519IsCanonical(PublicKey) == 0 || EC25519::Ge25519HasSmallOrder(PublicKey) != 0)
	{
		res = false;
	}
	else if (res == true && EC25519::Ge25519FromBytesNegateVarTime(A, PublicKey) != 0)
	{
		res = false;
	}

	if (res == true)
	{
		Digest->Update(Signature, 0, 32);
		Digest->Update(PublicKey, 0, 32);
		Digest->Update(Message, 0, Message.size());
		Digest->Finalize(h, 0);

		EC25519::Sc25519Reduce(h);
		EC25519::Ge25519DoubleScalarMultVarTime(R, h, A, Signature, 32);
		EC25519::Ge25519ToBytes(rcheck, R);

		res = (EC25519::Sc25519Verify(rcheck, Signature, 32) == 0 && IntegerTools::Compare(Signature, 0, rcheck, 0, 32) == true);
	}

	return res;
}

void ECDSABase::GenerateKeyPair(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::vector<uint8_t> &Seed, std::unique_ptr<IDigest> &Digest)
{
	EC25519::ge25519p3 A = { 0 };

	Digest->Compute(Seed, PrivateKey);

	EC25519::Sc25519Clamp(PrivateKey);
	EC25519::Ge25519ScalarBase(A, PrivateKey);
	EC25519::Ge25519P3ToBytes(PublicKey, A);

	MemoryTools::Copy(Seed, 0, PrivateKey, 0, EC25519::EC25519_SEED_SIZE);
	MemoryTools::Copy(PublicKey, 0, PrivateKey, EC25519::EC25519_SEED_SIZE, PublicKey.size());
}

bool ECDSABase::Sign(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<IDigest> &Digest)
{
	bool res;

	MemoryTools::Copy(Message, 0, Signature, EC25519::EC25519_SIGNATURE_SIZE, Message.size());
	res = Ed25519Sign(Signature, Message, PrivateKey, Digest);

	if (res == false)
	{
		MemoryTools::Clear(Signature, 0, Signature.size());
		res = false;
	}

	return res;
}

bool ECDSABase::Verify(std::vector<uint8_t> &Message, const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &PublicKey, std::unique_ptr<IDigest> &Digest)
{
	const size_t MSGLEN = Signature.size() - EC25519::EC25519_SIGNATURE_SIZE;
	std::vector<uint8_t> tmpm(MSGLEN);
	bool res;

	MemoryTools::Copy(Signature, EC25519::EC25519_SIGNATURE_SIZE, tmpm, 0, tmpm.size());

	res = Ed25519Verify(Signature, tmpm, PublicKey, Digest);

	if (res == false)
	{
		MemoryTools::Clear(Message, 0, Message.size());
	}
	else
	{
		Message.resize(tmpm.size());
		MemoryTools::Copy(tmpm, 0, Message, 0, tmpm.size());
	}

	return res;
}

NAMESPACE_ECDSAEND
