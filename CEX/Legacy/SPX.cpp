#include "SPX.h"
#include "Serpent.h"
#include "IntUtils.h"

NAMESPACE_BLOCK

using CEX::Utility::IntUtils;

void SPX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt16(Input, 0, Output, 0);
}

void SPX::DecryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	Decrypt16(Input, InOffset, Output, OutOffset);
}

void SPX::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_dfnRounds = 0;
		_isEncryption = false;
		_isInitialized = false;

		IntUtils::ClearVector(_expKey);
		IntUtils::ClearVector(_legalKeySizes);
		IntUtils::ClearVector(_legalRounds);
	}
}

void SPX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt16(Input, 0, Output, 0);
}

void SPX::EncryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	Encrypt16(Input, InOffset, Output, OutOffset);
}

void SPX::Initialize(bool Encryption, const KeyParams &KeyParam)
{
	if (KeyParam.Key().size() != 16 && KeyParam.Key().size() != 24 && KeyParam.Key().size() != 32 && KeyParam.Key().size() != 64)
		throw CryptoSymmetricCipherException("SPX:Initialize", "Invalid key size! Valid sizes are 16, 24, 32 and 64 bytes.");

	_isEncryption = Encryption;
	ExpandKey(KeyParam.Key());
}

void SPX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_isEncryption)
		Encrypt16(Input, 0, Output, 0);
	else
		Decrypt16(Input, 0, Output, 0);
}

void SPX::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (_isEncryption)
		Encrypt16(Input, InOffset, Output, OutOffset);
	else
		Decrypt16(Input, InOffset, Output, OutOffset);
}

// *** Key Schedule *** //

void SPX::ExpandKey(const std::vector<byte> &Key)
{
	unsigned int cnt = 0;
	unsigned int index = 0;
	unsigned int padSize = Key.size() < 32 ? 16 : Key.size() / 2;
	std::vector<uint> Wp(padSize, 0);
	unsigned int offset = 0;

	// less than 512 is default rounds
	if (Key.size() < 64)
		_dfnRounds = ROUNDS32;

	unsigned int keySize = 4 * (_dfnRounds + 1);

	// step 1: reverse copy key to temp array
	for (offset = Key.size(); offset > 0; offset -= 4)
		Wp[index++] = IntUtils::BytesToBe32(Key, offset - 4);

	// pad small key
	if (index < 8)
		Wp[index] = 1;

	// initialize the key
	std::vector<uint> Wk(keySize, 0);

	if (padSize == 16)
	{
		// 32 byte key
		// step 2: rotate k into w(k) ints
		for (unsigned int i = 8; i < 16; i++)
			Wp[i] = IntUtils::RotateLeft((Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);

		// copy to expanded key
		CopyVector(Wp, 8, Wk, 0, 8);
		
		// step 3: calculate remainder of rounds with rotating primitive
		for (unsigned int i = 8; i < keySize; i++)
			Wk[i] = IntUtils::RotateLeft((Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
	}
	else
	{
		// *extended*: 64 byte key
		// step 3: rotate k into w(k) ints, with extended polynominal
		// Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
		for (unsigned int i = 16; i < 32; i++)
			Wp[i] = IntUtils::RotateLeft((Wp[i - 16] ^ Wp[i - 13] ^ Wp[i - 11] ^ Wp[i - 10] ^ Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 16)), 11);

		// copy to expanded key
		CopyVector(Wp, 16, Wk, 0, 16);

		// step 3: calculate remainder of rounds with rotating primitive
		for (unsigned int i = 16; i < keySize; i++)
			Wk[i] = IntUtils::RotateLeft((Wk[i - 16] ^ Wk[i - 13] ^ Wk[i - 11] ^ Wk[i - 10] ^ Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
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

void SPX::Decrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	const unsigned int LRD = 4;
	unsigned int keyCtr = _expKey.size();

	// input round
	uint R3 = _expKey[--keyCtr] ^ IntUtils::BytesToBe32(Input, InOffset);
	uint R2 = _expKey[--keyCtr] ^ IntUtils::BytesToBe32(Input, InOffset + 4);
	uint R1 = _expKey[--keyCtr] ^ IntUtils::BytesToBe32(Input, InOffset + 8);
	uint R0 = _expKey[--keyCtr] ^ IntUtils::BytesToBe32(Input, InOffset + 12);

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
	} 
	while (keyCtr != LRD);

	// last round
	IntUtils::Be32ToBytes(R3 ^ _expKey[--keyCtr], Output, OutOffset);
	IntUtils::Be32ToBytes(R2 ^ _expKey[--keyCtr], Output, OutOffset + 4);
	IntUtils::Be32ToBytes(R1 ^ _expKey[--keyCtr], Output, OutOffset + 8);
	IntUtils::Be32ToBytes(R0 ^ _expKey[--keyCtr], Output, OutOffset + 12);
}

void SPX::Encrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	const int LRD = _expKey.size() - 5;
	int keyCtr = -1;

	// input round
	uint R0 = IntUtils::BytesToBe32(Input, InOffset + 12);
	uint R1 = IntUtils::BytesToBe32(Input, InOffset + 8);
	uint R2 = IntUtils::BytesToBe32(Input, InOffset + 4);
	uint R3 = IntUtils::BytesToBe32(Input, InOffset);

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
	} 
	while (keyCtr != LRD);

	// last round
	IntUtils::Be32ToBytes(_expKey[++keyCtr] ^ R0, Output, OutOffset + 12);
	IntUtils::Be32ToBytes(_expKey[++keyCtr] ^ R1, Output, OutOffset + 8);
	IntUtils::Be32ToBytes(_expKey[++keyCtr] ^ R2, Output, OutOffset + 4);
	IntUtils::Be32ToBytes(_expKey[++keyCtr] ^ R3, Output, OutOffset);
}

// *** Protected Methods *** //

void SPX::CopyVector(const std::vector<uint> &Input, unsigned int InOffset, std::vector<uint> &Output, unsigned int OutOffset, unsigned int Length)
{
	memcpy(&Output[OutOffset], &Input[InOffset], Length * sizeof(Input[InOffset]));
}

/// <remarks>
/// Apply the linear transformation to the register set
/// </remarks>
void SPX::LinearTransform(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint x0 = IntUtils::RotateLeft(R0, 13);
	uint x2 = IntUtils::RotateLeft(R2, 3);
	uint x1 = R1 ^ x0 ^ x2;
	uint x3 = R3 ^ x2 ^ x0 << 3;

	R1 = IntUtils::RotateLeft(x1, 1);
	R3 = IntUtils::RotateLeft(x3, 7);
	R0 = IntUtils::RotateLeft(x0 ^ R1 ^ R3, 5);
	R2 = IntUtils::RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
}

/// <remarks>
/// Apply the inverse of the linear transformation to the register set
/// </remarks>
void SPX::InverseTransform(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint x2 = IntUtils::RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
	uint x0 = IntUtils::RotateRight(R0, 5) ^ R1 ^ R3;
	uint x3 = IntUtils::RotateRight(R3, 7);
	uint x1 = IntUtils::RotateRight(R1, 1);

	R3 = x3 ^ x2 ^ x0 << 3;
	R1 = x1 ^ x0 ^ x2;
	R2 = IntUtils::RotateRight(x2, 3);
	R0 = IntUtils::RotateRight(x0, 13);
}

NAMESPACE_BLOCKEND