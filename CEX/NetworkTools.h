// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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

#ifndef CEX_NETWORKTOOLS_H
#define CEX_NETWORKTOOLS_H

#include "CexDomain.h"
#include "IntegerTools.h"
#include "SocketBase.h"

NAMESPACE_TOOLS

using namespace Network;

/// <summary>
/// Network functions class
/// </summary>
class NetworkTools
{
public:

	//~~~IP Address~~~//

	/// <summary>
	/// Retrieves the local IPv4 address
	/// </summary>
	/// 
	/// <returns>The default interface ip address</returns>
	static ipv4_address GetIPv4Address();

	/// <summary>
	/// Retrieves the local IPv6 address
	/// </summary>
	/// 
	/// <returns>The default interface ip address</returns>
	static ipv6_address GetIPv6Address();

	/// <summary>
	/// Retrieves the local IPv4 address information for a remote host
	/// </summary>
	/// 
	/// <param name="Host">The hosts qualified name</param>
	/// <param name="Service">The service name</param>
	/// 
	/// <returns>The default interface ip address</returns>
	static ipv4_info GetIPv4Info(const std::string &Host, const std::string &Service);

	/// <summary>
	/// Retrieves the local IPv6 address information for a remote host
	/// </summary>
	/// 
	/// <param name="Host">The hosts qualified name</param>
	/// <param name="Service">The service name</param>
	/// 
	/// <returns>The default interface ip address</returns>
	static ipv6_info GetIPv6Info(const std::string &Host, const std::string &Service);

	/// <summary>
	/// Retrieves a list of ip addressees for each network interface on the system
	/// </summary>
	/// 
	/// <returns>The list of ip addresses</returns>
	static std::vector<std::string> GetIpAddressList();

	/// <summary>
	/// Retrieves the name of the connected peer
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// 
	/// <returns>The peers name</returns>
	static std::string GetPeerName(Socket &Source);

	/// <summary>
	/// Retrieves the name of the socket
	/// </summary>
	/// 
	/// <param name="Source">The source socket instance</param>
	/// 
	/// <returns>The sockets name</returns>
	static std::string GetSocketName(Socket &Source);

	/// <summary>
	/// Get the port number using the connection parameters
	/// </summary>
	/// 
	/// <param name="Name">The service name</param>
	/// <param name="Protocol">The protocol name</param>
	///
	/// <returns>The port number, or zero on failure</returns>
	static ushort PortNameToNumber(const std::string &Name, const std::string &Protocol);

	//~~~HTTP~~~//


};

NAMESPACE_TOOLSEND
#endif
