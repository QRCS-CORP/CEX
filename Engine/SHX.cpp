#include "SHX.h"
#include "Serpent.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IntUtils.h"
#include "DigestFromName.h"

NAMESPACE_BLOCK

void SHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt16(Input, 0, Output, 0);
}

void SHX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt16(Input, InOffset, Output, OutOffset);
}

void SHX::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_dfnRounds = 0;
		_ikmSize = 0;
		_isEncryption = false;
		_isInitialized = false;

		CEX::Utility::IntUtils::ClearVector(_expKey);
		CEX::Utility::IntUtils::ClearVector(_hkdfInfo);
		CEX::Utility::IntUtils::ClearVector(_legalKeySizes);
		CEX::Utility::IntUtils::ClearVector(_legalRounds);

		if (_kdfEngine != 0)
		{
			_kdfEngine->Destroy();
			if (_destroyEngine)
				delete _kdfEngine;
		}
	}
}

void SHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt16(Input, 0, Output, 0);
}

void SHX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt16(Input, InOffset, Output, OutOffset);
}

void SHX::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
	int dgtsze = GetIkmSize(_kdfEngineType);
	int dgtblk = GetSaltSize(_kdfEngineType);
	const std::vector<byte> &key = KeyParam.Key();
	std::string msg = "Invalid key size! Key must be either 16, 24, 32, 64 bytes or, (length - IKm length: {" +
		CEX::Utility::IntUtils::ToString(dgtsze) + "} bytes) + multiple of {" + CEX::Utility::IntUtils::ToString(dgtblk) + "} block size.";

	if (key.size() < _legalKeySizes[0])
		throw CryptoSymmetricCipherException("SHX:Initialize", msg);
	if (key.size() > _legalKeySizes[3] && (key.size() - dgtsze) % dgtblk != 0)
		throw CryptoSymmetricCipherException("SHX:Initialize", msg);

	for (size_t i = 0; i < _legalKeySizes.size(); ++i)
	{
		if (key.size() == _legalKeySizes[i])
			break;
		if (i == _legalKeySizes.size() - 1)
			throw CryptoSymmetricCipherException("SHX:Initialize", msg);
	}

	// get the kdf digest engine
	if (key.size() > MAX_STDKEY)
		_kdfEngine = GetDigest(_kdfEngineType);

	_isEncryption = Encryption;
	// expand the key
	ExpandKey(key);
	// ready to transform data
	_isInitialized = true;
}

void SHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_isEncryption)
		Encrypt16(Input, 0, Output, 0);
	else
		Decrypt16(Input, 0, Output, 0);
}

void SHX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (_isEncryption)
		Encrypt16(Input, InOffset, Output, OutOffset);
	else
		Decrypt16(Input, InOffset, Output, OutOffset);
}

// *** Key Schedule *** //

void SHX::ExpandKey(const std::vector<byte> &Key)
{
	// min possible size for hkdf extended is 768 bit (96 bytes)
	if (Key.size() > MAX_STDKEY)
	{
		// hkdf key expansion
		SecureExpand(Key);
	}
	else
	{
		// standard rijndael key expansion + k512
		StandardExpand(Key);
	}
}

void SHX::SecureExpand(const std::vector<byte> &Key)
{
	// expanded key size
	size_t keySize = 4 * (_dfnRounds + 1);
	// hkdf return array
	size_t keyBytes = keySize * 4;
	std::vector<byte> rawKey(keyBytes, 0);
	size_t saltSize = Key.size() - _ikmSize;

	// salt must be divisible of hash blocksize
	if (saltSize % _kdfEngine->BlockSize() != 0)
		saltSize = saltSize - saltSize % _kdfEngine->BlockSize();

	// hkdf input
	std::vector<byte> hkdfKey(_ikmSize, 0);
	std::vector<byte> hkdfSalt(saltSize, 0);

	// copy hkdf key and salt from user key
	memcpy(&hkdfKey[0], &Key[0], _ikmSize);
	memcpy(&hkdfSalt[0], &Key[_ikmSize], saltSize);

	// HKDF generator expands array using an SHA512 HMAC
	CEX::Mac::HMAC hmac(_kdfEngine);
	CEX::Generator::HKDF gen(&hmac);
	gen.Initialize(hkdfSalt, hkdfKey, _hkdfInfo);
	gen.Generate(rawKey);

	// initialize working key
	std::vector<uint> wK(keySize, 0);
	// copy bytes to working key
	memcpy(&wK[0], &rawKey[0], keyBytes);

	_expKey = wK;
}

void SHX::StandardExpand(const std::vector<byte> &Key)
{
	uint cnt = 0;
	uint index = 0;
	size_t padSize = Key.size() < 32 ? 16 : Key.size() / 2;
	std::vector<uint> Wp(padSize, 0);
	size_t offset = 0;

	// less than 512 is default rounds
	if (Key.size() < 64)
		_dfnRounds = ROUNDS32;

	size_t keySize = 4 * (_dfnRounds + 1);

	// step 1: reverse copy key to temp array
	for (offset = Key.size(); offset > 0; offset -= 4)
		Wp[index++] = CEX::Utility::IntUtils::BytesToBe32(Key, offset - 4);

	// pad small key
	if (index < 8)
		Wp[index] = 1;

	// initialize the key
	std::vector<uint> Wk(keySize, 0);

	if (padSize == 16)
	{
		// 32 byte key
		// step 2: rotate k into w(k) ints
		for (size_t i = 8; i < 16; i++)
			Wp[i] = CEX::Utility::IntUtils::RotateLeft((uint)(Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);

		// copy to expanded key
		CopyVector(Wp, 8, Wk, 0, 8);

		// step 3: calculate remainder of rounds with rotating primitive
		for (size_t i = 8; i < keySize; i++)
			Wk[i] = CEX::Utility::IntUtils::RotateLeft((uint)(Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
	}
	else
	{
		// *extended*: 64 byte key
		// step 3: rotate k into w(k) ints, with extended polynominal
		// Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
		for (size_t i = 16; i < 32; i++)
			Wp[i] = CEX::Utility::IntUtils::RotateLeft((uint)(Wp[i - 16] ^ Wp[i - 13] ^ Wp[i - 11] ^ Wp[i - 10] ^ Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 16)), 11);

		// copy to expanded key
		CopyVector(Wp, 16, Wk, 0, 16);

		// step 3: calculate remainder of rounds with rotating primitive
		for (size_t i = 16; i < keySize; i++)
			Wk[i] = CEX::Utility::IntUtils::RotateLeft((uint)(Wk[i - 16] ^ Wk[i - 13] ^ Wk[i - 11] ^ Wk[i - 10] ^ Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
	}

	// step 4: create the working keys by processing with the Sbox and IP
	while (cnt < keySize - 4)
	{
		Sb3(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb2(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb1(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb0(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb7(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb6(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb5(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb4(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
	}

	// last round
	Sb3(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]);

	_expKey = Wk;
}

// *** Rounds Processing *** //

void SHX::Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = 4;
	size_t keyCtr = _expKey.size();

	// input round
	uint R3 = _expKey[--keyCtr] ^ CEX::Utility::IntUtils::BytesToBe32(Input, InOffset);
	uint R2 = _expKey[--keyCtr] ^ CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4);
	uint R1 = _expKey[--keyCtr] ^ CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8);
	uint R0 = _expKey[--keyCtr] ^ CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12);

	// process 8 round blocks
	do
	{
		Ib7(R0, R1, R2, R3);
		R3 ^= _expKey[--keyCtr];
		R2 ^= _expKey[--keyCtr];
		R1 ^= _expKey[--keyCtr];
		R0 ^= _expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib6(R0, R1, R2, R3);
		R3 ^= _expKey[--keyCtr];
		R2 ^= _expKey[--keyCtr];
		R1 ^= _expKey[--keyCtr];
		R0 ^= _expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib5(R0, R1, R2, R3);
		R3 ^= _expKey[--keyCtr];
		R2 ^= _expKey[--keyCtr];
		R1 ^= _expKey[--keyCtr];
		R0 ^= _expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib4(R0, R1, R2, R3);
		R3 ^= _expKey[--keyCtr];
		R2 ^= _expKey[--keyCtr];
		R1 ^= _expKey[--keyCtr];
		R0 ^= _expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib3(R0, R1, R2, R3);
		R3 ^= _expKey[--keyCtr];
		R2 ^= _expKey[--keyCtr];
		R1 ^= _expKey[--keyCtr];
		R0 ^= _expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib2(R0, R1, R2, R3);
		R3 ^= _expKey[--keyCtr];
		R2 ^= _expKey[--keyCtr];
		R1 ^= _expKey[--keyCtr];
		R0 ^= _expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib1(R0, R1, R2, R3);
		R3 ^= _expKey[--keyCtr];
		R2 ^= _expKey[--keyCtr];
		R1 ^= _expKey[--keyCtr];
		R0 ^= _expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib0(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != LRD)
		{
			R3 ^= _expKey[--keyCtr];
			R2 ^= _expKey[--keyCtr];
			R1 ^= _expKey[--keyCtr];
			R0 ^= _expKey[--keyCtr];
			InverseTransform(R0, R1, R2, R3);
		}

	} while (keyCtr != LRD);

	// last round
	CEX::Utility::IntUtils::Be32ToBytes(R3 ^ _expKey[--keyCtr], Output, OutOffset);
	CEX::Utility::IntUtils::Be32ToBytes(R2 ^ _expKey[--keyCtr], Output, OutOffset + 4);
	CEX::Utility::IntUtils::Be32ToBytes(R1 ^ _expKey[--keyCtr], Output, OutOffset + 8);
	CEX::Utility::IntUtils::Be32ToBytes(R0 ^ _expKey[--keyCtr], Output, OutOffset + 12);
}

void SHX::Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = _expKey.size() - 5;
	int keyCtr = -1;

	// input round
	uint R0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12);
	uint R1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8);
	uint R2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4);
	uint R3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset);

	// process 8 round blocks
	do
	{
		R0 ^= _expKey[++keyCtr];
		R1 ^= _expKey[++keyCtr];
		R2 ^= _expKey[++keyCtr];
		R3 ^= _expKey[++keyCtr];
		Sb0(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= _expKey[++keyCtr];
		R1 ^= _expKey[++keyCtr];
		R2 ^= _expKey[++keyCtr];
		R3 ^= _expKey[++keyCtr];
		Sb1(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= _expKey[++keyCtr];
		R1 ^= _expKey[++keyCtr];
		R2 ^= _expKey[++keyCtr];
		R3 ^= _expKey[++keyCtr];
		Sb2(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= _expKey[++keyCtr];
		R1 ^= _expKey[++keyCtr];
		R2 ^= _expKey[++keyCtr];
		R3 ^= _expKey[++keyCtr];
		Sb3(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= _expKey[++keyCtr];
		R1 ^= _expKey[++keyCtr];
		R2 ^= _expKey[++keyCtr];
		R3 ^= _expKey[++keyCtr];
		Sb4(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= _expKey[++keyCtr];
		R1 ^= _expKey[++keyCtr];
		R2 ^= _expKey[++keyCtr];
		R3 ^= _expKey[++keyCtr];
		Sb5(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= _expKey[++keyCtr];
		R1 ^= _expKey[++keyCtr];
		R2 ^= _expKey[++keyCtr];
		R3 ^= _expKey[++keyCtr];
		Sb6(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= _expKey[++keyCtr];
		R1 ^= _expKey[++keyCtr];
		R2 ^= _expKey[++keyCtr];
		R3 ^= _expKey[++keyCtr];
		Sb7(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != LRD)
			LinearTransform(R0, R1, R2, R3);

	} while (keyCtr != LRD);

	// last round
	CEX::Utility::IntUtils::Be32ToBytes(_expKey[++keyCtr] ^ R0, Output, OutOffset + 12);
	CEX::Utility::IntUtils::Be32ToBytes(_expKey[++keyCtr] ^ R1, Output, OutOffset + 8);
	CEX::Utility::IntUtils::Be32ToBytes(_expKey[++keyCtr] ^ R2, Output, OutOffset + 4);
	CEX::Utility::IntUtils::Be32ToBytes(_expKey[++keyCtr] ^ R3, Output, OutOffset);
}

/// <remarks>
/// Apply the linear transformation to the register set
/// </remarks>
void SHX::LinearTransform(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint x0 = CEX::Utility::IntUtils::RotateLeft(R0, 13);
	uint x2 = CEX::Utility::IntUtils::RotateLeft(R2, 3);
	uint x1 = R1 ^ x0 ^ x2;
	uint x3 = R3 ^ x2 ^ x0 << 3;

	R1 = CEX::Utility::IntUtils::RotateLeft(x1, 1);
	R3 = CEX::Utility::IntUtils::RotateLeft(x3, 7);
	R0 = CEX::Utility::IntUtils::RotateLeft(x0 ^ R1 ^ R3, 5);
	R2 = CEX::Utility::IntUtils::RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
}

/// <remarks>
/// Apply the inverse of the linear transformation to the register set
/// </remarks>
void SHX::InverseTransform(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint x2 = CEX::Utility::IntUtils::RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
	uint x0 = CEX::Utility::IntUtils::RotateRight(R0, 5) ^ R1 ^ R3;
	uint x3 = CEX::Utility::IntUtils::RotateRight(R3, 7);
	uint x1 = CEX::Utility::IntUtils::RotateRight(R1, 1);

	R3 = x3 ^ x2 ^ x0 << 3;
	R1 = x1 ^ x0 ^ x2;
	R2 = CEX::Utility::IntUtils::RotateRight(x2, 3);
	R0 = CEX::Utility::IntUtils::RotateRight(x0, 13);
}

CEX::Digest::IDigest* SHX::GetDigest(CEX::Enumeration::Digests DigestType)
{
	try
	{
		return CEX::Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (...)
	{
		throw CryptoSymmetricCipherException("CipherStream:GetKeyEngine", "The digest could not be instantiated!");
	}
}

int SHX::GetIkmSize(CEX::Enumeration::Digests DigestType)
{
	switch (DigestType)
	{
	case CEX::Enumeration::Digests::Blake256:
	case CEX::Enumeration::Digests::Keccak256:
	case CEX::Enumeration::Digests::SHA256:
	case CEX::Enumeration::Digests::Skein256:
		return 32;
	case CEX::Enumeration::Digests::Blake512:
	case CEX::Enumeration::Digests::Keccak512:
	case CEX::Enumeration::Digests::SHA512:
	case CEX::Enumeration::Digests::Skein512:
		return 64;
	case CEX::Enumeration::Digests::Skein1024:
		return 128;
	default:
		throw CryptoSymmetricCipherException("RHX:GetDigestSize", "The digest type is not supported!");
	}
}

int SHX::GetSaltSize(CEX::Enumeration::Digests DigestType)
{
	switch (DigestType)
	{
	case CEX::Enumeration::Digests::Blake256:
	case CEX::Enumeration::Digests::Skein256:
		return 32;
	case CEX::Enumeration::Digests::Blake512:
	case CEX::Enumeration::Digests::SHA256:
	case CEX::Enumeration::Digests::Skein512:
		return 64;
	case CEX::Enumeration::Digests::SHA512:
	case CEX::Enumeration::Digests::Skein1024:
		return 128;
	case CEX::Enumeration::Digests::Keccak256:
		return 136;
	case CEX::Enumeration::Digests::Keccak512:
		return 72;
	default:
		throw CryptoSymmetricCipherException("RHX:GetBlockSize", "The digest type is not supported!");
	}
}

NAMESPACE_BLOCKEND