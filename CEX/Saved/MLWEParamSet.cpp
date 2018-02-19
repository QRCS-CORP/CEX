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

#include "MLWEParamSet.h"

NAMESPACE_MODULELWE

//~~~Constructor~~~//

MLWEParamSet::MLWEParamSet()
	:
	m_authEngine(BlockCiphers::None),
	m_cipherTextSize(0),
	m_paramSetName(MLWEParams::None),
	m_privateKeySize(0),
	m_publicKeySize(0),
	m_seedSize(0)
{
}

MLWEParamSet::MLWEParamSet(MLWEParams ParamSetName, BlockCiphers AuthEngine)
{
	Load(ParamSetName, AuthEngine);
}

MLWEParamSet::MLWEParamSet(const std::vector<byte> &ParamArray)
{
	m_authEngine = static_cast<BlockCiphers>(ParamArray[0]);
	m_paramSetName = static_cast<MLWEParams>(ParamArray[1]);

	Load(m_paramSetName, m_authEngine);
}

MLWEParamSet::~MLWEParamSet()
{
	Reset();
}

const BlockCiphers MLWEParamSet::AuthenticationEngine()
{
	return m_authEngine;
}

const uint MLWEParamSet::CipherTextSize()
{
	return m_cipherTextSize;
}

const MLWEParams MLWEParamSet::ParamSetName()
{
	return m_paramSetName;
}

const uint MLWEParamSet::PrivateKeySize()
{
	return m_privateKeySize;
}

const uint MLWEParamSet::PublicKeySize()
{
	return m_publicKeySize;
}

const uint MLWEParamSet::SeedSize()
{
	return m_seedSize;
}

//~~~Public Functions~~~//

void MLWEParamSet::Load(MLWEParams ParamSetName, BlockCiphers AuthEngine)
{
	m_authEngine = AuthEngine;
	m_paramSetName = ParamSetName;
	uint k = static_cast<uint>(ParamSetName);
	m_cipherTextSize = (k * PUBPOLY_SIZE) + (3 * SEED_SIZE);
	m_privateKeySize = (k * PUBPOLY_SIZE) + (k * SECPOLY_SIZE) + SEED_SIZE;
	m_publicKeySize = (k * PUBPOLY_SIZE) + SEED_SIZE;
	m_seedSize = SEED_SIZE;
}

void MLWEParamSet::Reset()
{
	m_authEngine = BlockCiphers::None;
	m_paramSetName = MLWEParams::None;
	m_cipherTextSize = 0;
	m_privateKeySize = 0;
	m_publicKeySize = 0;
	m_seedSize = 0;
}

std::vector<byte> MLWEParamSet::ToBytes()
{
	std::vector<byte> ret(2);
	ret[0] = static_cast<byte>(m_authEngine);
	ret[1] = static_cast<byte>(m_paramSetName);

	return ret;
}

NAMESPACE_MODULELWEEND
