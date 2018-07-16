// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_TKX_H
#define CEX_TKX_H

#include "IBlockCipher.h"

NAMESPACE_BLOCK

/// 
/// internal
/// 

class TKX final : public IBlockCipher
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const std::string CIPHER_NAME;
	static const std::string CLASS_NAME;
	static const std::string DEF_DSTINFO;
	static const size_t MAX_ROUNDS = 64;
	static const size_t MIN_ROUNDS = 32;
	static const uint PHI = 0x9E3779B9UL;
	// size of state buffer subtracted parallel size calculations
	static const size_t STATE_PRECACHED = 2048;

	BlockCipherExtensions m_cprExtension;
	bool m_destroyEngine;
	std::vector<byte> m_distCode;
	size_t m_distCodeMax;
	std::vector<ulong> m_expKey;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	std::unique_ptr<IKdf> m_kdfGenerator;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_rndCount;

public:

	TKX(const TKX&) = delete;

	TKX& operator=(const TKX&) = delete;

	TKX(BlockCipherExtensions CipherExtensionType = BlockCipherExtensions::None)
	{

	}

	TKX(Kdf::IKdf* Kdf)
	{

	}

	~TKX()
	{

	}

	const size_t BlockSize()
	{
		return BLOCK_SIZE;
	}

	const BlockCipherExtensions CipherExtension()
	{
		return m_cprExtension;
	}

	std::vector<byte>& DistributionCode()
	{
		return m_distCode;
	}

	const size_t DistributionCodeMax()
	{
		return m_distCodeMax;
	}

	const BlockCiphers Enumeral()
	{
		return Enumeration::BlockCiphers::THX;
	}

	const bool IsEncryption()
	{
		return m_isEncryption;
	}

	const bool IsInitialized()
	{
		return m_isInitialized;
	}

	const std::vector<SymmetricKeySize>& LegalKeySizes()
	{
		return m_legalKeySizes;
	}

	const std::string Name()
	{
		return std::string("TKX");
	}

	const size_t Rounds()
	{
		return m_rndCount;
	}

	const size_t StateCacheSize()
	{
		return 0;
	}

	void DecryptBlock(const std::vector<byte>& Input, std::vector<byte>& Output)
	{

	}

	void DecryptBlock(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
	{

	}

	void EncryptBlock(const std::vector<byte>& Input, std::vector<byte>& Output)
	{

	}

	void EncryptBlock(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
	{

	}

	void Initialize(bool Encryption, ISymmetricKey & KeyParams)
	{

	}

	void Transform(const std::vector<byte>& Input, std::vector<byte>& Output)
	{

	}

	void Transform(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
	{

	}

	void Transform512(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
	{

	}

	void Transform1024(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
	{

	}

	void Transform2048(const std::vector<byte>& Input, const size_t InOffset, std::vector<byte>& Output, const size_t OutOffset)
	{

	}

	private:

		template <typename Array>
		static void Decrypt(Array &Input, size_t InOffset, Array &Output, size_t OutOffset, size_t Rounds)
		{

		}

		template <typename Array>
		static void Encrypt(Array &Input, size_t InOffset, Array &Output, size_t OutOffset, size_t Rounds)
		{

		}
};

NAMESPACE_BLOCKEND
#endif
