#ifndef CEX_CIPHERDESCRIPTION_H
#define CEX_CIPHERDESCRIPTION_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "BlockCipherExtensions.h"
#include "CipherModes.h"
#include "IVSizes.h"
#include "KeySizes.h"
#include "MemoryStream.h"
#include "PaddingModes.h"

NAMESPACE_PROCESSING

using Enumeration::BlockCiphers;
using Enumeration::BlockCipherExtensions;
using Enumeration::CipherModes;
using Enumeration::IVSizes;
using Enumeration::KeySizes;
using Enumeration::PaddingModes;
using IO::MemoryStream;

/// <summary>
/// Contains symmetric cipher configuration information
/// </summary>
class CipherDescription
{
private:

	static const uint HDR_SIZE = 9;

	byte m_cipherType;
	byte m_cipherExtensionType;
	byte m_cipherModeType;
	byte m_ivSize;
	ushort m_keySize;
	byte m_paddingType;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor
	/// </summary>
	CipherDescription();

	/// <summary>
	/// Initialize a CipherDescription struct with parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The symmetric cipher type</param>
	/// <param name="CipherExtensionType">The kdf engine type used to power the key schedule in HX-extended ciphers</param>
	/// <param name="CipherModeType">The type of symmetric cipher mode</param>
	/// <param name="PaddingType">The type of symmetric cipher padding mode</param>
	/// <param name="KeySize">The cipher key size in bytes</param>
	/// <param name="IvSize">Size of the cipher nonce or initialization ector</param>
	CipherDescription(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, CipherModes CipherModeType, PaddingModes PaddingType, KeySizes KeySize, IVSizes IvSize);

	/// <summary>
	/// Copy constructor
	/// </summary>
	explicit CipherDescription(CipherDescription* Description);

	/// <summary>
	/// Initialize the CipherDescription structure using a serialized cipher description stream
	/// </summary>
	/// 
	/// <param name="DescriptionStream">The Stream containing the CipherDescription</param>
	explicit CipherDescription(const MemoryStream &DescriptionStream);

	/// <summary>
	/// Initialize the CipherDescription structure using a serialized cipher description array
	/// </summary>
	/// 
	/// <param name="DescriptionArray">The byte array containing the CipherDescription</param>
	explicit CipherDescription(const std::vector<byte> &DescriptionArray);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CipherDescription();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The symmetric block-cipher type
	/// </summary>
	const BlockCiphers CipherType();

	/// <summary>
	/// Read Only: The KDF engine used to power the key schedule HX-extended ciphers
	/// </summary>
	const BlockCipherExtensions CipherExtensionType();

	/// <summary>
	/// Read Only: The type of symmetric cipher mode
	/// </summary>
	const CipherModes CipherModeType();

	/// <summary>
	/// Read Only: Size of the ciphers nonce or initialization vector
	/// </summary>
	const IVSizes IvSize();

	/// <summary>
	/// Read Only: The symmetric ciphers input-key size
	/// </summary>
	const ushort KeySize() const;

	/// <summary>
	/// Read Only: The type of symmetric cipher padding mode
	/// </summary>
	const PaddingModes PaddingType();

	//~~~Public Functions~~~//

	//~~~AES~~~//

	/// <summary>
	/// An AES-128 preset using CBC mode and PKCS7 padding
	/// </summary>
	static CipherDescription* AES128CBC();

	/// <summary>
	/// An AES-128 preset using CTR mode
	/// </summary>
	static CipherDescription* AES128CTR();

	/// <summary>
	/// An AES-128 preset using the AEAD GCM mode
	/// </summary>
	static CipherDescription* AES128GCM();

	/// <summary>
	/// An AES-256 preset using CBC mode and PKCS7 padding
	/// </summary>
	static CipherDescription* AES256CBC();

	/// <summary>
	/// An AES-256 preset using CTR mode
	/// </summary>
	static CipherDescription* AES256CTR();

	/// <summary>
	/// An AES-256 preset using the AEAD GCM mode
	/// </summary>
	static CipherDescription* AES256GCM();

	//~~~RHX~~~//

	/// <summary>
	/// An Rijndael-256 HX-extended preset using CBC mode, PKCS7 padding, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* RHX256CBC();

	/// <summary>
	/// An Rijndael-256 HX-extended preset using CTR mode, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* RHX256CTR();

	/// <summary>
	/// An Rijndael-256 HX-extended preset using the AEAD GCM mode, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* RHX256GCM();

	/// <summary>
	/// An Rijndael-512 HX-extended preset using CBC mode, PKCS7 padding, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* RHX512CBC();

	/// <summary>
	/// An Rijndael-512 HX-extended preset using CTR mode, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* RHX512CTR();

	/// <summary>
	/// An Rijndael-512 HX-extended preset using the AEAD GCM mode, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* RHX512GCM();

	//~~~RSX~~~//

	/// <summary>
	/// An Rijndael-256 HX-extended preset using CBC mode, PKCS7 padding, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* RSX256CBC();

	/// <summary>
	/// An Rijndael-256 HX-extended preset using CTR mode, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* RSX256CTR();

	/// <summary>
	/// An Rijndael-256 HX-extended preset using the AEAD GCM mode, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* RSX256GCM();

	/// <summary>
	/// An Rijndael-512 HX-extended preset using CBC mode, PKCS7 padding, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* RSX512CBC();

	/// <summary>
	/// An Rijndael-512 HX-extended preset using CTR mode, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* RSX512CTR();

	/// <summary>
	/// An Rijndael-512 HX-extended preset using the AEAD GCM mode, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* RSX512GCM();

	//~~~Serpent~~~//

	/// <summary>
	/// An Serpent-256 preset using CBC mode and PKCS7 padding
	/// </summary>
	static CipherDescription* SERPENT256CBC();

	/// <summary>
	/// An Serpent-256 preset using CTR mode
	/// </summary>
	static CipherDescription* SERPENT256CTR();

	/// <summary>
	/// An Serpent-256 preset using the AEAD GCM mode
	/// </summary>
	static CipherDescription* SERPENT256GCM();

	//~~~SHX~~~//

	/// <summary>
	/// An Serpent-256 HX-extended preset using CBC mode, PKCS7 padding, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* SHX256CBC();

	/// <summary>
	/// An Serpent-256 HX-extended preset using CTR mode, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* SHX256CTR();

	/// <summary>
	/// An Serpent-256 HX-extended preset using the AEAD GCM mode, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* SHX256GCM();

	/// <summary>
	/// An Serpent-512 HX-extended preset using CBC mode, PKCS7 padding, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* SHX512CBC();

	/// <summary>
	/// An Serpent-512 HX-extended preset using CTR mode, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* SHX512CTR();

	/// <summary>
	/// An Serpent-512 HX-extended preset using the AEAD GCM mode, and an HKDF(SHA256) key schedule
	/// </summary>
	static CipherDescription* SHX512GCM();

	//~~~SSX~~~//

	/// <summary>
	/// An Serpent-256 HX-extended preset using CBC mode, PKCS7 padding, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* SSX256CBC();

	/// <summary>
	/// An Serpent-256 HX-extended preset using CTR mode, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* SSX256CTR();

	/// <summary>
	/// An Serpent-256 HX-extended preset using the AEAD GCM mode, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* SSX256GCM();

	/// <summary>
	/// An Serpent-512 HX-extended preset using CBC mode, PKCS7 padding, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* SSX512CBC();

	/// <summary>
	/// An Serpent-512 HX-extended preset using CTR mode, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* SSX512CTR();

	/// <summary>
	/// An Serpent-512 HX-extended preset using the AEAD GCM mode, and an SHAKE-256 key schedule
	/// </summary>
	static CipherDescription* SSX512GCM();

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Input">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(CipherDescription &Input);

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode();

	/// <summary>
	/// Get the header size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static int GetHeaderSize();

	/// <summary>
	/// Reset all struct members
	/// </summary>
	void Reset();

	/// <summary>
	/// Convert the CipherDescription structure to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the CipherDescription</returns>
	std::vector<byte> ToBytes();

	/// <summary>
	/// Convert the CipherDescription structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the CipherDescription</returns>
	MemoryStream* ToStream();
};

NAMESPACE_PROCESSINGEND
#endif
