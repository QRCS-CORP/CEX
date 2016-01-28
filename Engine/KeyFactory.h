#ifndef _CEXENGINE_KEYFACTORY_H
#define _CEXENGINE_KEYFACTORY_H

#include "Common.h"
#include "CipherDescription.h"
#include "CipherKey.h"
#include "CryptoProcessingException.h"
#include "CSPRsg.h"
#include "Digests.h"
#include "KeyGenerator.h"
#include "KeyParams.h"
#include "MemoryStream.h"
#include "SeedGenerators.h"

NAMESPACE_PROCESSING

using CEX::Common::CipherDescription;
using CEX::Common::KeyParams;
using CEX::Exception::CryptoProcessingException;
using CEX::Enumeration::Digests;
using CEX::Enumeration::SeedGenerators;
using CEX::IO::MemoryStream;
using namespace CEX::Enumeration;

/// <summary>
/// <h5>KeyFactory: Used to create or extract a CipherKey file.</h5>
/// 
/// <list type="bullet">
/// <item><description>Constructors may use a fully qualified path to a key file, or the keys file stream.</description></item>
/// <item><description>The <see cref="Create(CipherDescription, KeyParams)"/> method requires a populated KeyParams class.</description></item>
/// <item><description>The <see cref="Create(CipherDescription, SeedGenerators, Digests)"/> method auto-generate keying material.</description></item>
/// <item><description>The Extract() method retrieves a populated cipher key (CipherKey), and key material (KeyParams), from the key file.</description></item>
/// </list>
/// </summary>
/// 
/// <example>
/// <description>Example using the <see cref="Create(CipherDescription, SeedGenerators, Digests)"/> overload:</description>
/// <code>
/// // create the key file
/// new KeyFactory(KeyPath).Create(description);
/// </code>
/// 
/// <description>Example using the <see cref="Extract(out CipherKey, out KeyParams)"/> method:</description>
/// <code>
/// // local vars
/// keyparam KeyParams;
/// CipherKey header;
/// 
/// new KeyFactory(KeyPath).Extract(out header, out keyparam);
/// </code>
/// </example>
/// 
/// <revisionHistory>
/// <revision date="2015/01/23" version="1.3.0.0">Initial release</revision>
/// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
/// </revisionHistory>
/// 
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.CipherKey">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherKey Structure</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">VTDev.Libraries.CEXEngine.Crypto.Processing.Structures CipherDescription Structure</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs Enumeration</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests Enumeration</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyGenerator">VTDev.Libraries.CEXEngine.Crypto.Processing.Factory KeyGenerator class</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams">VTDev.Libraries.CEXEngine.Crypto.Processing.Structure KeyParams class</seealso>
/// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Processing.CipherStream">VTDev.Libraries.CEXEngine.Crypto.Processing CipherStream class</seealso>
class KeyFactory
{
private:
	bool _isDestroyed;
	CEX::IO::MemoryStream _keyStream;
	KeyFactory() { }

public:

	/// <summary>
	/// Initialize this class with a memory stream; key will be written to the stream
	/// </summary>
	/// 
	/// <param name="KeyStream">The fully qualified path to the key file to be read or created</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if a null stream is passed</exception>
	KeyFactory(MemoryStream &KeyStream)
		:
		_isDestroyed(false),
		_keyStream(KeyStream)
	{
	}


	/// <summary>
	/// Finalizer: ensure resources are destroyed
	/// </summary>
	~KeyFactory()
	{
		Destroy();
	}

	/// <summary>
	/// Create a single use key file using a <see cref="KeyParams"/> containing the key material, and a <see cref="CipherDescription"/> containing the cipher implementation details
	/// </summary>
	/// 
	/// <param name="Description">The <see cref="CipherDescription">Cipher Description</see> containing the cipher details</param>
	/// <param name="KeyParam">An initialized and populated key material container</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if a KeyParams member is null, but specified in the Header or a Header parameter does not match a KeyParams value</exception>
	void Create(CipherDescription &Description, KeyParams &KeyParam)
	{
		if (KeyParam.Key().size() != Description.KeySize())
			throw CryptoProcessingException("KeyFactory:Create", "The key parameter does not match the key size specified in the Header!");

		if ((unsigned int)Description.IvSize() > 0)
		{
			if (KeyParam.IV().size() != (unsigned int)Description.IvSize())
				throw CryptoProcessingException("KeyFactory:Create", "The KeyParam IV size does not align with the IVSize setting in the Header!");
		}
		if (Description.MacSize() > 0)
		{
			if (KeyParam.Ikm().size() != Description.MacSize())
				throw CryptoProcessingException("KeyFactory:Create", "Header MacSize does not align with the size of the KeyParam IKM!");
		}

		if (_keyStream == 0)
			_keyStream = new MemoryStream();

		CEX::Seed::CSPRsg rnd;
		std::vector<byte> hdr = CipherKey(&Description, rnd.GetBytes(16), rnd.GetBytes(16)).ToBytes();
		_keyStream->Write(hdr, 0, hdr.size());
		MemoryStream* tmp = KeyParams::Serialize(KeyParam);
		std::vector<byte> key = tmp->ToArray();
		_keyStream->Write(key, 0, key.size());
		delete tmp;
	}

	/// <summary>
	/// Create a single use Key file using a manual description of the cipher parameters.
	/// </summary>
	/// 
	/// <param name="KeyParam">An initialized and populated key material container</param>
	/// <param name="EngineType">The Cryptographic <see cref="SymmetricEngines">Engine</see> type</param>
	/// <param name="KeySize">The cipher Key Size in bytes</param>
	/// <param name="IvSize">Size of the cipher <see cref="IVSizes">Initialization Vector</see></param>
	/// <param name="CipherType">The type of <see cref="CipherModes">Cipher Mode</see></param>
	/// <param name="PaddingType">The type of cipher <see cref="PaddingModes">Padding Mode</see></param>
	/// <param name="BlockSize">The cipher <see cref="BlockSizes">Block Size</see></param>
	/// <param name="Rounds">The number of diffusion <see cref="RoundCounts">Rounds</see></param>
	/// <param name="KdfEngine">The <see cref="Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
	/// <param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
	/// <param name="MacEngine">The HMAC <see cref="Digests">Digest</see> engine used to authenticate a message file encrypted with this key</param>
	/// 
	/// <exception cref="System.ArgumentNullException">Thrown if a KeyParams member is null, but specified in the Header</exception>
	/// <exception cref="System.ArgumentOutOfRangeException">Thrown if a Header parameter does not match a KeyParams value</exception>
	void Create(KeyParams &KeyParam, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType,
		PaddingModes PaddingType, BlockSizes BlockSize, RoundCounts Rounds, Digests KdfEngine, int MacSize, Digests MacEngine)
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
			MacSize,
			MacEngine);

		Create(dsc, KeyParam);
	}

	/// <summary>
	/// Extract a KeyParams and CipherKey
	/// </summary>
	/// 
	/// <param name="KeyHeader">The <see cref="CipherKey"/> that receives the cipher description, key id, and extension key</param>
	/// <param name="KeyParam">The <see cref="KeyParams"/> container that receives the key material from the file</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if the key file could not be found or a Header parameter does not match the keystream length</exception>
	void Extract(CipherKey &KeyHeader, KeyParams &KeyParam)
	{
		KeyHeader = CipherKey(_keyStream);
		CipherDescription dsc = KeyHeader.Description;

		if (_keyStream.Length() < dsc.KeySize() + (unsigned int)dsc.IvSize() + dsc.MacSize() + KeyHeader.GetHeaderSize())
			throw new CryptoProcessingException("KeyFactory:Extract", "The size of the key file does not align with the CipherKey sizes! Key is corrupt.");

		_keyStream.Seek(KeyHeader.GetHeaderSize(), CEX::IO::SeekOrigin::Begin);
		KeyParam = KeyParams::DeSerialize(&_keyStream);
	}

	void Destroy()
	{
		if (!_isDestroyed)
		{
			try
			{
				
			}
			catch { }

			_isDestroyed = true;
		}
	}
};

NAMESPACE_PROCESSINGEND
#endif