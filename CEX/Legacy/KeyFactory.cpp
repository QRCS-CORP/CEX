#include "KeyFactory.h"
#include "CryptoProcessingException.h"
#include "CSP.h"
#include "KeyGenerator.h"

// TODO: rewrite? 
NAMESPACE_PRCFACTORY

using Exception::CryptoProcessingException;
using Provider::CSP;
using Key::Symmetric::KeyGenerator;

void KeyFactory::Create(CipherDescription &Description, Providers SeedEngine, Digests HashEngine)
{
	CSP rnd;
	KeyGenerator keyGen(SeedEngine, HashEngine, rnd.GetBytes(16));
	SymmetricKey key = keyGen.GetKeyParams(Description.KeySize(), (uint)Description.IvSize(), Description.MacKeySize());

	Create(Description, key);
}

void KeyFactory::Create(CipherDescription &Description, SymmetricKey &KeyParam)
{
	if (KeyParam.Key().size() != Description.KeySize())
		throw CryptoProcessingException("KeyFactory:Create", "The key parameter does not match the key size specified in the Header!");

	if ((uint)Description.IvSize() > 0)
	{
		if (KeyParam.Nonce().size() != (uint)Description.IvSize())
			throw CryptoProcessingException("KeyFactory:Create", "The KeyParam Nonce size does not align with the IVSize setting in the Header!");
	}
	if (Description.MacKeySize() > 0)
	{
		if (KeyParam.Info().size() != Description.MacKeySize())
			throw CryptoProcessingException("KeyFactory:Create", "Header MacKeySize does not align with the size of the KeyParam Info!");
	}

	CSP rnd;
	CipherKey ck(Description, rnd.GetBytes(16), rnd.GetBytes(16));
	std::vector<byte> hdr = ck.ToBytes();
	m_keyStream->Write(hdr, 0, hdr.size());
	MemoryStream* tmp = SymmetricKey::Serialize(KeyParam);
	std::vector<byte> key = tmp->ToArray();
	m_keyStream->Write(key, 0, key.size());
	delete tmp;
}

void KeyFactory::Create(SymmetricKey &KeyParam, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType, 
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

void KeyFactory::Extract(CipherKey &KeyHeader, SymmetricKey &KeyParam)
{
	KeyHeader = CipherKey(*m_keyStream);
	const CipherDescription dsc = KeyHeader.Description();

	if (m_keyStream->Length() < dsc.KeySize() + (uint)dsc.IvSize() + dsc.MacKeySize() + KeyHeader.GetHeaderSize())
		throw CryptoProcessingException("KeyFactory:Extract", "The size of the key file does not align with the CipherKey sizes! Key is corrupt.");

	m_keyStream->Seek(KeyHeader.GetHeaderSize(), IO::SeekOrigin::Begin);
	KeyParam = *SymmetricKey::DeSerialize(*m_keyStream);
}

NAMESPACE_PRCFACTORYEND
