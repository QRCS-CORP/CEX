#ifndef CEX_MACBASE_H
#define CEX_MACBASE_H

#include "IMac.h"
#include "Macs.h"
#include "SymmetricKey.h"
#include "SymmetricSecureKey.h"

NAMESPACE_MAC

using Enumeration::Macs;
using Cipher::SymmetricKey;
using Cipher::SymmetricSecureKey;

/// <summary>
/// The MAC base class; this is not an operable class
/// </summary>
class MacBase : public IMac
{
private:

	size_t m_blockSize;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	Macs m_macEnumeral;
	std::string m_macName;
	size_t m_minKeySize;
	size_t m_minSaltSize;
	size_t m_tagSize;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	MacBase(const MacBase&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	MacBase& operator=(const MacBase&) = delete;

	/// <summary>
	/// Default constructor: the default constructor is restricted, this function has been deleted
	/// </summary>
	MacBase() = delete;

	/// <summary>
	/// Constructor: instantiate this class (private member)
	/// </summary>
	///
	/// <param name="BlockSize">The input block size of the MAC</param>
	/// <param name="Enumeral">The MACs enumeration name</param>
	/// <param name="Name">The MACs formal class name</param>
	/// <param name="KeySizes">A vector of legal SymmetricKeySize used by the MAC</param>
	/// <param name="MinimumKey">The minimum number of bytes of key that will initialize the generator</param>
	/// <param name="MinimumSalt">The minimum number of bytes of salt that will initialize the generator</param>
	/// <param name="TagSize">The output MAC tag size</param>
	MacBase(size_t BlockSize, Macs Enumeral, std::string &Name, std::vector<SymmetricKeySize> &KeySizes, size_t MinimumKey, size_t MinimumSalt, size_t TagSize);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~MacBase();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Macs internal blocksize in bytes
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The prngs type name
	/// </summary>
	const Macs Enumeral() override;

	/// <summary>
	/// Read Only: Available MAC Key Sizes in SymmetricKeySize containers
	/// </summary>
	std::vector<SymmetricKeySize> LegalKeySizes() const override;

	/// <summary>
	/// Read Only: Minimum recommended initialization key size in bytes
	/// </summary>
	const size_t MinimumKeySize() override;

	/// <summary>
	/// Read Only: Minimum recommended initialization salt size in bytes
	/// </summary>
	const size_t MinimumSaltSize() override;

	/// <summary>
	/// The MAC generators formal class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: Size of returned mac in bytes
	/// </summary>
	const size_t TagSize() override;

};

NAMESPACE_MACEND
#endif
