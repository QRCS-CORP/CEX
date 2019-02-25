#ifndef CEX_KDFBASE_H
#define CEX_KDFBASE_H

#include "IKdf.h"
#include "SymmetricKey.h"
#include "SymmetricSecureKey.h"

NAMESPACE_KDF

using Cipher::SymmetricKey;
using Cipher::SymmetricSecureKey;

/// <summary>
/// The KDF base class; this is not an operable class
/// </summary>
class KdfBase : public IKdf
{
private:

	Kdfs m_kdfEnumeral;
	std::string m_kdfName;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_minKeySize;
	size_t m_minSaltSize;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	KdfBase(const KdfBase&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	KdfBase& operator=(const KdfBase&) = delete;

	/// <summary>
	/// Default constructor: the default constructor is restricted, this function has been deleted
	/// </summary>
	KdfBase() = delete;

	/// <summary>
	/// Constructor: instantiate this class (private member)
	/// </summary>
	///
	/// <param name="Enumeral">The KDFs enumeration name</param>
	/// <param name="MinimumKey">The minimum number of bytes allowed to initialize the generator</param>
	/// <param name="MinimumSalt">The minimum number of bytes used to salt the generator</param>
	/// <param name="Name">The KDFs formal class name</param>
	/// <param name="KeySizes">A vector of legal SymmetricKeySize used by the KDF</param>
	KdfBase(Kdfs Enumeral, size_t MinimumKey, size_t MinimumSalt, std::string &Name, std::vector<SymmetricKeySize> &KeySizes);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~KdfBase();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The prngs type name
	/// </summary>
	const Kdfs Enumeral() override;

	/// <summary>
	/// Read Only: Available KDF Key Sizes in SymmetricKeySize containers
	/// </summary>
	const std::vector<SymmetricKeySize> LegalKeySizes() override;

	/// <summary>
	/// Read Only: Minimum recommended initialization key size in bytes
	/// </summary>
	const size_t MinimumKeySize() override;

	/// <summary>
	/// Read Only: Minimum recommended salt size in bytes
	/// </summary>
	const size_t MinimumSaltSize() override;

	/// <summary>
	/// The KDF generators formal class name
	/// </summary>
	const std::string Name() override;
};

NAMESPACE_KDFEND
#endif
