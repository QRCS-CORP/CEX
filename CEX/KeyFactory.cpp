#include "KeyFactory.h"
#include "CryptoProcessingException.h"
#include "CSPRsg.h"
#include "KeyGenerator.h"

NAMESPACE_PRCFACTORY

using CEX::Exception::CryptoProcessingException;
using CEX::Seed::CSPRsg;
using CEX::Common::KeyGenerator;

void KeyFactory::Create(CipherDescription &Description, SeedGenerators SeedEngine, Digests HashEngine)
{
	CSPRsg rnd;
	KeyGenerator keyGen(SeedEngine, HashEngine, rnd.GetBytes(16));
	KeyParams* key = keyGen.GetKeyParams(Description.KeySize(), (uint)Description.IvSize(), Description.MacKeySize());

	Create(Description, *key);
}

void KeyFactory::Create(CipherDescription &Description, KeyParams &KeyParam)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.Key().size() != Description.KeySize())
		throw CryptoProcessingException("KeyFactory:Create", "The key parameter does not match the key size specified in the Header!");

	if ((uint)Description.IvSize() > 0)
	{
		if (KeyParam.IV().size() != (uint)Description.IvSize())
			throw CryptoProcessingException("KeyFactory:Create", "The KeyParam IV size does not align with the IVSize setting in the Header!");
	}
	if (Description.MacKeySize() > 0)
	{
		if (KeyParam.Ikm().size() != Description.MacKeySize())
			throw CryptoProcessingException("KeyFactory:Create", "Header MacKeySize does not align with the size of the KeyParam IKM!");
	}
#endif

	CSPRsg rnd;
	CipherKey ck(Description, rnd.GetBytes(16), rnd.GetBytes(16));
	std::vector<byte> hdr = ck.ToBytes();
	m_keyStream->Write(hdr, 0, hdr.size());
	MemoryStream* tmp = KeyParams::Serialize(KeyParam);
	std::vector<byte> key = tmp->ToArray();
	m_keyStream->Write(key, 0, key.size());
	delete tmp;
}

void KeyFactory::Create(KeyParams &KeyParam, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType, 
	BlockSizes BlockSize, RoundCounts Rounds, Digests KdfEngine, int MacKeySize, Digests MacEngine)
{
	CipherDescription dsc(
		EngineType,
		KeySize,
		IvSize,
		CipherType,
		PaddingType,
		BlockSize,
		Rounds,
		KdfEngine,
		MacKeySize,
		MacEngine);

	Create(dsc, KeyParam);
}

void KeyFactory::Extract(CipherKey &KeyHeader, KeyParams &KeyParam)
{
	KeyHeader = CipherKey(*m_keyStream);
	const CipherDescription dsc = KeyHeader.Description();

#if defined(CPPEXCEPTIONS_ENABLED)
	if (m_keyStream->Length() < dsc.KeySize() + (uint)dsc.IvSize() + dsc.MacKeySize() + KeyHeader.GetHeaderSize())
		throw CryptoProcessingException("KeyFactory:Extract", "The size of the key file does not align with the CipherKey sizes! Key is corrupt.");
#endif

	m_keyStream->Seek(KeyHeader.GetHeaderSize(), CEX::IO::SeekOrigin::Begin);
	KeyParam = *KeyParams::DeSerialize(*m_keyStream);
}

NAMESPACE_PRCFACTORYEND
