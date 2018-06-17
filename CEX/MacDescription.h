#ifndef CEX_MACDESCRIPTION_H
#define CEX_MACDESCRIPTION_H

#include "CexDomain.h"
#include "BlockCipherExtensions.h"
#include "BlockCiphers.h"
#include "Digests.h"
#include "Macs.h"
#include "MemoryStream.h"


NAMESPACE_PROCESSING

using Enumeration::BlockCipherExtensions;
using Enumeration::BlockCiphers;
using Enumeration::Digests;
using Enumeration::Macs;

using IO::MemoryStream;

/// <summary>
/// The MacDescription structure.
/// <para>Used in conjunction with the MacStream class.
/// Contains all the necessary settings required to recreate a Mac instance.</para>
/// </summary>
/// 
/// <example>
/// <description>Populating a MacDescription for an Hmac:</description>
/// <code>
///    MacDescription md(Macs::HMAC, Digests.SHA512);			// key size in bytes
/// </code>
/// </example>
class MacDescription
{
private:

	static const uint MACHDR_SIZE = 4;

	byte m_macType;
	byte m_macDigest;
	byte m_blockCipher;
	byte m_cipherExtension;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	MacDescription& operator=(const MacDescription&) = delete;

	/// <summary>
	/// Default constructor
	/// </summary>
	MacDescription();

	/// <summary>
	/// Initialize the structure with parameters for a block-cipher based generator
	/// </summary>
	/// 
	/// <param name="MacType">The type of Mac generator</param>
	/// <param name="CipherType">The symmetric block cipher Engine type</param>
	/// <param name="CipherExtensionType">The KDF used in exdtended HX ciphers</param>
	MacDescription(Macs MacType, BlockCiphers CipherType = BlockCiphers::RHX, BlockCipherExtensions CipherExtensionType = BlockCipherExtensions::None);

	/// <summary>
	/// Initialize the structure with parameters for a hash based generator
	/// </summary>
	/// 
	/// <param name="MacType">The type of Mac generator</param>
	/// <param name="MacDigestType">The hash-digest used by the Mac</param>
	MacDescription(Macs MacType, Digests MacDigestType);

	/// <summary>
	/// Initialize the MacDescription structure using a serialized mac description stream
	/// </summary>
	/// 
	/// <param name="DescriptionStream">The Stream containing the MacDescription</param>
	explicit MacDescription(const MemoryStream &DescriptionStream);

	/// <summary>
	/// Initialize the MacDescription structure using a serialized mac description array
	/// </summary>
	/// 
	/// <param name="DescriptionArray">The byte array containing the MacDescription</param>
	explicit MacDescription(const std::vector<byte> &DescriptionArray);

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The block-cipher extension type
	/// </summary>
	const BlockCipherExtensions CipherExtension();

	/// <summary>
	/// Read Only: The symmetric block-cipher type
	/// </summary>
	const BlockCiphers CipherType();

	/// <summary>
	/// Read Only: The MAC digest type
	/// </summary>
	const Digests MacDigest();

	/// <summary>
	/// Read Only: The Mac configuration type
	/// </summary>
	const Macs MacType();

	//~~~Public Functions~~~//

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Input">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(MacDescription &Input);

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
	/// Convert the MacDescription structure as a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the MacDescription</returns>
	std::vector<byte> ToBytes();

	/// <summary>
	/// Convert the MacDescription structure to a MemoryStream
	/// </summary>
	/// 
	/// <returns>The MemoryStream containing the MacDescription</returns>
	MemoryStream* ToStream();
};

NAMESPACE_PROCESSINGEND
#endif
