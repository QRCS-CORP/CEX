#include "KeyGenerator.h"
#include "CSPRsg.h"
#include "DigestFromName.h"
#include "HMAC.h"
#include "IntUtils.h"
#include "SeedFromName.h"

NAMESPACE_COMMON

void KeyGenerator::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_ctrLength = 0;
		CEX::Utility::IntUtils::ClearVector(_ctrVector);

		if (_hashEngine != 0)
			delete _hashEngine;
		if (_seedEngine != 0)
			delete _seedEngine;
	}
}

CEX::Common::KeyParams* KeyGenerator::GetKeyParams(const unsigned int KeySize, const unsigned int IVSize, unsigned int IKMSize)
{
	CEX::Common::KeyParams* kp = new CEX::Common::KeyParams();

	if (KeySize > 0)
		kp->Key() = Generate(KeySize);
	if (IVSize > 0)
		kp->IV() = Generate(IVSize);
	if (IKMSize > 0)
		kp->Ikm() = Generate(IKMSize);

	return kp;
}

void KeyGenerator::GetBytes(std::vector<byte> &Data)
{
	std::vector<byte> rand = Generate(Data.size());
	memcpy(&Data[0], &rand[0], rand.size());
}

std::vector<byte> KeyGenerator::GetBytes(unsigned int Size)
{
	return Generate(Size);
}

void KeyGenerator::Reset()
{
	// reset seed engine
	if (_seedEngine != 0)
		delete _seedEngine;
	_seedEngine = GetSeedEngine(_rngType);

	// reset hash engine
	if (_hashEngine != 0)
		delete _hashEngine;
	_hashEngine = GetDigestEngine(_dgtType);

	// if absent, generate the initial counter
	if (_ctrLength == 0)
	{
		_ctrLength = DEFCTR_SIZE;
		_ctrVector.resize(_ctrLength, (byte)0);
		CEX::Seed::CSPRsg pool;
		pool.GetBytes(_ctrVector);
	}
}

std::vector<byte> KeyGenerator::Generate(unsigned int Size)
{
	std::vector<byte> key(Size);
	// get the first block
	std::vector<byte> rand = GetBlock();
	unsigned int blockSize = rand.size();

	if (Size < blockSize)
	{
		memcpy(&key[0], &rand[0], Size);
	}
	else
	{
		// copy first block
		memcpy(&key[0], &rand[0], blockSize);

		unsigned int offset = blockSize;
		unsigned int alnSize = Size - (Size % blockSize);

		// fill the key array
		while (offset < alnSize)
		{
			memcpy(&key[offset], &GetBlock()[0], blockSize);
			offset += blockSize;
		}

		// process unaligned block
		if (alnSize < Size)
		{
			memcpy(&key[offset], &GetBlock()[0], Size - offset);
		}
	}

	return key;
}

std::vector<byte> KeyGenerator::GetBlock()
{
	// generate seed; 2x input block size per NIST sp800-90b
	unsigned int seedLen = _hashEngine->BlockSize() * 2;
	std::vector<byte> seed(seedLen);
	unsigned int saltLen = seedLen - _ctrLength;

	// increment the counter
	Increment(_ctrVector);
	// prepend the counter
	memcpy(&seed[0], &_ctrVector[0], _ctrLength);
	// create the salt
	std::vector<byte> stmp = _seedEngine->GetBytes(saltLen);
	// copy into seed
	memcpy(&seed[_ctrLength], &stmp[0], saltLen);

	// special case for sha-2
	if (_dgtType == CEX::Enumeration::Digests::SHA256 || _dgtType == CEX::Enumeration::Digests::SHA512)
	{
		// hmac key size is digest return size per rfc 2104
		std::vector<byte> key = _seedEngine->GetBytes(_hashEngine->DigestSize());
		CEX::Mac::HMAC* mac = new CEX::Mac::HMAC(_hashEngine);
		mac->Initialize(key);
		std::vector<byte> output(mac->MacSize());
		mac->ComputeMac(seed, output);
		return output;
	}
	else
	{
		// other implemented digests do not require hmac
		std::vector<byte> output(_hashEngine->DigestSize());
		_hashEngine->ComputeHash(seed, output);
		return output;
	}
}

CEX::Digest::IDigest* KeyGenerator::GetDigestEngine(CEX::Enumeration::Digests DigsetType)
{
	try
	{
		return CEX::Helper::DigestFromName::GetInstance(DigsetType);
	}
	catch (...)
	{
		throw CEX::Exception::CryptoGeneratorException("KeyGenerator:GetDigestEngine", "The digest could not be instantiated!");
	}
}

CEX::Seed::ISeed* KeyGenerator::GetSeedEngine(CEX::Enumeration::SeedGenerators SeedType)
{
	try
	{
		return CEX::Helper::SeedFromName::GetInstance(SeedType);
	}
	catch (...)
	{
		throw CEX::Exception::CryptoGeneratorException("KeyGenerator:GetSeedEngine", "The prng could not be instantiated!");
	}
}

void KeyGenerator::Increment(std::vector<byte> &Counter)
{
	long i = Counter.size();
	while (--i >= 0 && ++Counter[i] == 0) {}
}

NAMESPACE_COMMONEND