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

#include "RLWEParamSet.h"

NAMESPACE_RINGLWE

//~~~Constructor~~~//

RLWEParamSet::RLWEParamSet()
	:
	m_authEngine(BlockCiphers::None),
	m_cipherTextSize(0),
	m_paramSetName(RLWEParams::None),
	m_privateKeySize(0),
	m_publicKeySize(0),
	m_seedSize(0)
{
}

RLWEParamSet::RLWEParamSet(RLWEParams ParamSetName, BlockCiphers AuthEngine)
{
	Load(ParamSetName, AuthEngine);
}

RLWEParamSet::RLWEParamSet(const std::vector<byte> &ParamArray)
{
	m_authEngine = static_cast<BlockCiphers>(ParamArray[0]);
	m_paramSetName = static_cast<RLWEParams>(ParamArray[1]);

	Load(m_paramSetName, m_authEngine);
}

RLWEParamSet::~RLWEParamSet()
{
	Reset();
}

const BlockCiphers RLWEParamSet::AuthenticationEngine()
{
	return m_authEngine;
}

const uint RLWEParamSet::CipherTextSize()
{
	return m_cipherTextSize;
}

const RLWEParams RLWEParamSet::ParamSetName()
{
	return m_paramSetName;
}

const uint RLWEParamSet::PrivateKeySize()
{
	return m_privateKeySize;
}

const uint RLWEParamSet::PublicKeySize()
{
	return m_publicKeySize;
}

const uint RLWEParamSet::SeedSize()
{
	return m_seedSize;
}

//~~~Public Functions~~~//

void RLWEParamSet::Load(RLWEParams ParamSetName, BlockCiphers AuthEngine)
{
	m_authEngine = AuthEngine;
	m_paramSetName = ParamSetName;
	m_cipherTextSize = Q12289N1024_CPTSIZE;
	m_privateKeySize = Q12289N1024_PRISIZE;
	m_publicKeySize = Q12289N1024_PUBSIZE;
	m_seedSize = SEED_SIZE;
}

void RLWEParamSet::Reset()
{
	m_authEngine = BlockCiphers::None;
	m_paramSetName = RLWEParams::None;
	m_cipherTextSize = 0;
	m_privateKeySize = 0;
	m_publicKeySize = 0;
	m_seedSize = 0;
}

std::vector<byte> RLWEParamSet::ToBytes()
{
	std::vector<byte> ret(2);
	ret[0] = static_cast<byte>(m_authEngine);
	ret[1] = static_cast<byte>(m_paramSetName);

	return ret;
}

NAMESPACE_RINGLWEEND
