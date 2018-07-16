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

#include "MPKCParamSet.h"

NAMESPACE_MCELIECE

//~~~Constructor~~~//

MPKCParamSet::MPKCParamSet()
	:
	m_authEngine(BlockCiphers::None),
	m_cipherTextSize(0),
	m_paramSetName(MPKCParams::None),
	m_privateKeySize(0),
	m_publicKeySize(0),
	m_seedSize(0)
{
}

MPKCParamSet::MPKCParamSet(MPKCParams ParamSetName, BlockCiphers AuthEngine)
{
	Load(ParamSetName, AuthEngine);
}

MPKCParamSet::MPKCParamSet(const std::vector<byte> &ParamArray)
{
	m_authEngine = static_cast<BlockCiphers>(ParamArray[0]);
	m_paramSetName = static_cast<MPKCParams>(ParamArray[1]);

	Load(m_paramSetName, m_authEngine);
}

MPKCParamSet::~MPKCParamSet()
{
	Reset();
}

const BlockCiphers MPKCParamSet::AuthenticationEngine()
{
	return m_authEngine;
}

const uint MPKCParamSet::CipherTextSize()
{
	return m_cipherTextSize;
}

const MPKCParams MPKCParamSet::ParamSetName()
{
	return m_paramSetName;
}

const uint MPKCParamSet::PrivateKeySize()
{
	return m_privateKeySize;
}

const uint MPKCParamSet::PublicKeySize()
{
	return m_publicKeySize;
}

const uint MPKCParamSet::SeedSize()
{
	return m_seedSize;
}

//~~~Public Functions~~~//

void MPKCParamSet::Load(MPKCParams ParamSetName, BlockCiphers AuthEngine)
{
	m_authEngine = AuthEngine;
	m_paramSetName = ParamSetName;
	m_seedSize = SEED_SIZE;

	if (m_paramSetName == MPKCParams::M12T62)
	{
		m_cipherTextSize = M12T62_CPTSIZE;
		m_privateKeySize = M12T62_PRISIZE;
		m_publicKeySize = M12T62_PUBSIZE;
	}
}

void MPKCParamSet::Reset()
{
	m_authEngine = BlockCiphers::None;
	m_paramSetName = MPKCParams::None;
	m_cipherTextSize = 0;
	m_privateKeySize = 0;
	m_publicKeySize = 0;
	m_seedSize = 0;
}

std::vector<byte> MPKCParamSet::ToBytes()
{
	std::vector<byte> ret(2);
	ret[0] = static_cast<byte>(m_authEngine);
	ret[1] = static_cast<byte>(m_paramSetName);

	return ret;
}

NAMESPACE_MCELIECEEND
