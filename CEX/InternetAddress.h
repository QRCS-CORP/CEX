#ifndef CEX_INTERNETADRESS_H
#define CEX_INTERNETADRESS_H

#include "CexDomain.h"
#include "IntegerTools.h"

NAMESPACE_ROOT

using Tools::IntegerTools;

/// <summary>
/// The IPv4 address structure
/// </summary>
typedef struct ipv4_address
{
	uint8_t a1;
	uint8_t a2;
	uint8_t a3;
	uint8_t a4;

	//~~~Constructorss~~~//

	/// <summary>
	/// Default constructor; initializes to all zeroes
	/// </summary>
	ipv4_address()
		:
		a1(0),
		a2(0),
		a3(0),
		a4(0)
	{
	}

	/// <summary>
	/// The primary constructor
	/// </summary>
	///
	/// <param name="A1">The first octet</param>
	/// <param name="A2">The second octet</param>
	/// <param name="A3">The third octet</param>
	/// <param name="A4">The fourth octet</param>
	ipv4_address(uint8_t A1, uint8_t A2, uint8_t A3, uint8_t A4)
		:
		a1(A1),
		a2(A2),
		a3(A3),
		a4(A4)
	{
	}

	/// <summary>
	/// Secondary constructor
	/// </summary>
	///
	/// <param name="Address">A pointer to a uint8_t array containing the ip address</param>
	ipv4_address(uint8_t* Address)
		:
		a1(Address[0]), 
		a2(Address[1]), 
		a3(Address[2]), 
		a4(Address[3]) 
	{
	}

	/// <summary>
	/// The destructor
	/// </summary>
	~ipv4_address()
	{
		a1 = 0;
		a2 = 0;
		a3 = 0;
		a4 = 0;
	}

	//~~~Operators~~~//

	/// <summary>
	/// Copy constructor
	/// </summary>
	///
	/// <param name="Source">The copy source</param>
	ipv4_address(const ipv4_address &Source)
		:
		a1(Source.a1),
		a2(Source.a2),
		a3(Source.a3),
		a4(Source.a4)
	{
	}

	/// <summary>
	/// Move constructor
	/// </summary>
	///
	/// <param name="Source">The move source</param>
	ipv4_address(ipv4_address &&Source) noexcept
		:
		a1(std::move(Source.a1)),
		a2(std::move(Source.a2)),
		a3(std::move(Source.a3)),
		a4(std::move(Source.a4))
	{
	}

	/// <summary>
	/// Copy assignment operator
	/// </summary>
	///
	/// <param name="Source">The copy source</param>
	/// 
	/// <returns>A copy of the address</returns>
	ipv4_address& operator=(const ipv4_address &Source)
	{
		a1 = Source.a1;
		a2 = Source.a2;
		a3 = Source.a3;
		a4 = Source.a4;

		return *this;
	}

	/// <summary>
	/// Move assignment operator
	/// </summary>
	///
	/// <param name="Source">The move source</param>
	/// 
	/// <returns>The moved address</returns>
	ipv4_address& operator=(ipv4_address&& Source) noexcept
	{
		std::swap(a1, Source.a1);
		std::swap(a2, Source.a1);
		std::swap(a3, Source.a1);
		std::swap(a4, Source.a1);

		return *this;
	}

	/// <summary>
	/// Test an address for equivalance
	/// </summary>
	///
	/// <param name="Source">The address to compare</param>
	/// 
	/// <returns>Returns true for an equal address</returns>
	bool operator==(const ipv4_address &Source) const
	{
		return a1 == Source.a1 &&
			a2 == Source.a2 &&
			a3 == Source.a3 &&
			a4 == Source.a4;
	}

	//~~~Static Functions~~~//

	/// <summary>
	/// Use the devices primary IPv4 address
	/// </summary>
	/// 
	/// <returns>The IPv4 primary address structure</returns>
	static const ipv4_address Any()
	{
		ipv4_address add(0, 0, 0, 0);

		return add;
	}

	/// <summary>
	/// Populate and address structure from a string representation
	/// </summary>
	///
	/// <param name="Address">The string address representation</param>
	/// 
	/// <returns>The IPv4 address structure</returns>
	static ipv4_address FromString(const std::string &Address)
	{
		CEXASSERT(Address.size() >= 7, "The address is of an invalid format.");

		const std::string DELIM = ".";
		ipv4_address add; 
		std::string sadd;
		size_t len;
		size_t pos;

		sadd = Address;
		len = sadd.find(DELIM);
		add.a1 = IntegerTools::FromString<uint8_t>(sadd, 0, len);
		pos = len + 1;
		len = Address.find(DELIM, pos);
		add.a2 = IntegerTools::FromString<uint8_t>(sadd, pos, len - pos);
		pos = len + 1;
		len = Address.find(DELIM, pos);
		add.a3 = IntegerTools::FromString<uint8_t>(sadd, pos, len - pos);
		pos = len + 1;
		add.a4 = IntegerTools::FromString<uint8_t>(sadd, pos, Address.size() - pos);

		return add;
	}

	/// <summary>
	/// Use the devices IPv4 loopback address
	/// </summary>
	/// 
	/// <returns>The IPv4 loopback address structure</returns>
	static const ipv4_address LoopBack()
	{
		ipv4_address add(127, 0, 0, 1);

		return add;
	}

	/// <summary>
	/// Convert an address structure to a string
	/// </summary>
	///
	/// <param name="Address">The IPv4 address structure</param>
	/// 
	/// <returns>The string representation of the address</returns>
	static std::string ToString(const ipv4_address &Address)
	{
		const std::string DELIM = ".";
		std::string sadd;

		sadd = IntegerTools::ToString(Address.a1);
		sadd += DELIM;
		sadd += IntegerTools::ToString(Address.a2);
		sadd += DELIM;
		sadd += IntegerTools::ToString(Address.a3);
		sadd += DELIM;
		sadd += IntegerTools::ToString(Address.a4);

		return sadd;
	}
} ipv4_address;


typedef struct ipv6_address
{
	/// <summary>
	/// IPv6 address prefixes
	/// </summary>
	enum class prefix_types
	{
		/// <summary>
		/// An link local address type, not globally routable, prefix: fe80
		/// </summary>
		link_local,
		/// <summary>
		/// A multicast address type, prefix: ff00
		/// </summary>
		multicast,
		/// <summary>
		/// A globally routable address type, prefix: 2000
		/// </summary>
		global,
		/// <summary>
		/// A unique local address type, not globally routable, prefix: fc00-fd00
		/// </summary>
		unique_local
	};

	uint8_t a1;
	uint8_t a2;
	uint8_t a3;
	uint8_t a4;
	uint8_t a5;
	uint8_t a6;
	uint8_t a7;
	uint8_t a8;
	uint8_t a9;
	uint8_t a10;
	uint8_t a11;
	uint8_t a12;
	uint8_t a13;
	uint8_t a14;
	uint8_t a15;
	uint8_t a16;

	//~~~Constructors~~~//

	/// <summary>
	/// Default constructor; initializes to all zeroes
	/// </summary>
	ipv6_address()
		:
		a1(0),
		a2(0),
		a3(0),
		a4(0),
		a5(0),
		a6(0),
		a7(0),
		a8(0),
		a9(0),
		a10(0),
		a11(0),
		a12(0),
		a13(0),
		a14(0),
		a15(0),
		a16(0)
	{
	}

	/// <summary>
	/// The primary constructor
	/// </summary>
	///
	/// <param name="A1">The first octet</param>
	/// <param name="A2">The second octet</param>
	/// <param name="A3">The third octet</param>
	/// <param name="A4">The fourth octet</param>
	/// <param name="A1">The fifth octet</param>
	/// <param name="A2">The sixth octet</param>
	/// <param name="A3">The seventh octet</param>
	/// <param name="A4">The eighth octet</param>
	/// <param name="A1">The ninth octet</param>
	/// <param name="A2">The tenth octet</param>
	/// <param name="A3">The eleventh octet</param>
	/// <param name="A4">The twelth octet</param>
	/// <param name="A1">The thirteenth octet</param>
	/// <param name="A2">The fourteenth octet</param>
	/// <param name="A3">The fifteenth octet</param>
	/// <param name="A4">The sixteenth octet</param>
	ipv6_address(uint8_t A1, uint8_t A2, uint8_t A3, uint8_t A4, uint8_t A5, uint8_t A6, uint8_t A7, uint8_t A8, 
		uint8_t A9, uint8_t A10, uint8_t A11, uint8_t A12, uint8_t A13, uint8_t A14, uint8_t A15, uint8_t A16)
		:
		a1(A1),
		a2(A2),
		a3(A3),
		a4(A4),
		a5(A5),
		a6(A6),
		a7(A7),
		a8(A8),
		a9(A9),
		a10(A10),
		a11(A11),
		a12(A12),
		a13(A13),
		a14(A14),
		a15(A15),
		a16(A16)
	{
	}

	/// <summary>
	/// Secondary constructor
	/// </summary>
	///
	/// <param name="A1">A pointer to a uint8_t array containing the ip address</param>
	ipv6_address(uint8_t* Address)
		:
		a1(Address[0]), 
		a2(Address[1]), 
		a3(Address[2]), 
		a4(Address[3]), 
		a5(Address[4]), 
		a6(Address[5]), 
		a7(Address[6]), 
		a8(Address[7]), 
		a9(Address[8]), 
		a10(Address[9]), 
		a11(Address[10]), 
		a12(Address[11]), 
		a13(Address[12]), 
		a14(Address[13]), 
		a15(Address[14]), 
		a16(Address[15]) 
	{
	}

	/// <summary>
	/// The destructor
	/// </summary>
	ipv6_address(std::string &Address)
	{
		ipv6_address tmpa = FromString(Address);

		a1 = tmpa.a1;
		a2 = tmpa.a2;
		a3 = tmpa.a3;
		a4 = tmpa.a4;
		a5 = tmpa.a5;
		a6 = tmpa.a6;
		a7 = tmpa.a7;
		a8 = tmpa.a8;
		a9 = tmpa.a9;
		a10 = tmpa.a10;
		a11 = tmpa.a11;
		a12 = tmpa.a12;
		a13 = tmpa.a13;
		a14 = tmpa.a14;
		a15 = tmpa.a15;
		a16 = tmpa.a16;
	}

	/// <summary>
	/// The destructor
	/// </summary>
	~ipv6_address()
	{
		a1 = 0;
		a2 = 0;
		a3 = 0;
		a4 = 0;
		a5 = 0;
		a6 = 0;
		a7 = 0;
		a8 = 0;
		a9 = 0;
		a10 = 0;
		a11 = 0;
		a12 = 0;
		a13 = 0;
		a14 = 0;
		a15 = 0;
		a16 = 0;
	}

	//~~~Operators~~~//

	/// <summary>
	/// Copy constructor
	/// </summary>
	///
	/// <param name="Source">The copy source</param>
	ipv6_address(const ipv6_address& Source)
		:
		a1(Source.a1),
		a2(Source.a2),
		a3(Source.a3),
		a4(Source.a4),
		a5(Source.a5),
		a6(Source.a6),
		a7(Source.a7),
		a8(Source.a8),
		a9(Source.a9),
		a10(Source.a10),
		a11(Source.a11),
		a12(Source.a12),
		a13(Source.a13),
		a14(Source.a14),
		a15(Source.a15),
		a16(Source.a16)
	{
	}

	/// <summary>
	/// Move constructor
	/// </summary>
	///
	/// <param name="Source">The move source</param>
	ipv6_address(ipv6_address&& Source) noexcept
		: 
		a1(std::move(Source.a1)),
		a2(std::move(Source.a2)),
		a3(std::move(Source.a3)),
		a4(std::move(Source.a4)),
		a5(std::move(Source.a5)),
		a6(std::move(Source.a6)),
		a7(std::move(Source.a7)),
		a8(std::move(Source.a8)),
		a9(std::move(Source.a9)),
		a10(std::move(Source.a10)),
		a11(std::move(Source.a11)),
		a12(std::move(Source.a12)),
		a13(std::move(Source.a13)),
		a14(std::move(Source.a14)),
		a15(std::move(Source.a15)),
		a16(std::move(Source.a16))
	{
	}

	/// <summary>
	/// Copy assignment operator
	/// </summary>
	///
	/// <param name="Source">The copy source</param>
	/// 
	/// <returns>A copy of the address</returns>
	ipv6_address& operator=(const ipv6_address& Source)
	{
		a1 = Source.a1;
		a2 = Source.a2;
		a3 = Source.a3;
		a4 = Source.a4;
		a5 = Source.a5;
		a6 = Source.a6;
		a7 = Source.a7;
		a8 = Source.a8;
		a9 = Source.a9;
		a10 = Source.a10;
		a11 = Source.a11;
		a12 = Source.a12;
		a13 = Source.a13;
		a14 = Source.a14;
		a15 = Source.a15;
		a16 = Source.a16;

		return *this;
	}

	/// <summary>
	/// Move assignment operator
	/// </summary>
	///
	/// <param name="Source">The move source</param>
	/// 
	/// <returns>The moved address</returns>
	ipv6_address& operator=(ipv6_address&& Source) noexcept
	{
		std::swap(a1, Source.a1);
		std::swap(a2, Source.a1);
		std::swap(a3, Source.a1);
		std::swap(a4, Source.a1);
		std::swap(a5, Source.a1);
		std::swap(a6, Source.a1);
		std::swap(a7, Source.a1);
		std::swap(a8, Source.a1);
		std::swap(a9, Source.a1);
		std::swap(a10, Source.a1);
		std::swap(a11, Source.a1);
		std::swap(a12, Source.a1);
		std::swap(a13, Source.a1);
		std::swap(a14, Source.a1);
		std::swap(a15, Source.a1);
		std::swap(a16, Source.a1);

		return *this;
	}

	/// <summary>
	/// Test an address for equivalance
	/// </summary>
	///
	/// <param name="Source">The address to compare</param>
	/// 
	/// <returns>Returns true for an equal address</returns>
	bool operator==(const ipv6_address& Source) const
	{
		return a1 == Source.a1 &&
			a2 == Source.a2 &&
			a3 == Source.a3 &&
			a4 == Source.a4 &&
			a5 == Source.a5 &&
			a6 == Source.a6 &&
			a7 == Source.a7 &&
			a8 == Source.a8 &&
			a9 == Source.a9 &&
			a10 == Source.a10 &&
			a11 == Source.a11 &&
			a12 == Source.a12 &&
			a13 == Source.a13 &&
			a14 == Source.a14 &&
			a15 == Source.a15 &&
			a16 == Source.a16;
	}

	//~~~Static Functions~~~//

	/// <summary>
	/// The IPv6 address routing prefix type
	/// </summary>
	/// 
	/// <returns>The routing prefix type</returns>
	prefix_types AddressType()
	{
		prefix_types ptype;

		if (a1 == 0xFF)
		{
			ptype = prefix_types::multicast;
		}
		else if (a1 == 0xFE)
		{
			ptype = prefix_types::link_local;
		}
		else if (a1 == 0xFD || a1 == 0xFC)
		{
			ptype = prefix_types::unique_local;
		}
		else
		{
			ptype = prefix_types::global;
		}

		return ptype;
	}

	/// <summary>
	/// Use the devices primary IPv6 address
	/// </summary>
	/// 
	/// <returns>The IPv6 primary address structure</returns>
	static const ipv6_address Any()
	{
		ipv6_address add(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

		return add;
	}

	/// <summary>
	/// Checks if the address is routable
	/// </summary>
	/// 
	/// <returns>Returns true if the address is globally routable</returns>
	bool IsRoutable()
	{
		prefix_types ptype;
		bool ret;

		ptype = AddressType();
		ret = (ptype != prefix_types::link_local && ptype != prefix_types::unique_local);

		return ret;
	}

	/// <summary>
	/// Populate and address structure from a string representation
	/// </summary>
	///
	/// <param name="Address">The string address representation</param>
	/// 
	/// <returns>The IPv6 address structure</returns>
	static ipv6_address FromString(const std::string &Address)
	{
		const std::string DELIM = std::string(":");
		const std::string DEMRK = std::string("::");
		const std::string LPBK = std::string("::1");
		const std::string DZONE = std::string("%");
		ipv6_address add;
		std::vector<uint8_t> tmpa(16);
		std::string sadd;
		std::string str1;
		std::string str2;
		size_t i;
		size_t j;
		size_t pos;

		pos = Address.find(DZONE);

		if (pos == std::string::npos)
		{
			sadd = Address;
		}
		else
		{
			sadd = Address.substr(0, pos);
		}

		pos = sadd.find(DEMRK);

		if (pos != std::string::npos)
		{
			if (sadd != LPBK)
			{
				str1 = sadd.substr(0, pos);
				str2 = sadd.substr(pos + 2);

				str1.erase(remove(str1.begin(), str1.end(), ':'), str1.end());
				str2.erase(remove(str2.begin(), str2.end(), ':'), str2.end());
				pos = tmpa.size() - (str2.size() / 2);

				for (i = 0, j = 0; i < str1.size(); i += 2, ++j)
				{
					tmpa[j] = IntegerTools::HexToInt<uint8_t>(str1, i);
				}

				for (i = 0, j = pos; i < str2.size(); i += 2, ++j)
				{
					tmpa[j] = IntegerTools::HexToInt<uint8_t>(str2, i);
				}
			}
			else
			{
				tmpa[tmpa.size() - 1] = 1;
			}
		}
		else
		{
			str1 = sadd;
			str1.erase(remove(str1.begin(), str1.end(), ':'), str1.end());

			for (i = 0; i < str1.size(); i += 2)
			{
				tmpa[i] = IntegerTools::HexToInt<uint8_t>(str1, i);
			}
		}

		add.a1 = tmpa[0];
		add.a2 = tmpa[1];
		add.a3 = tmpa[2];
		add.a4 = tmpa[3];
		add.a5 = tmpa[4];
		add.a6 = tmpa[5];
		add.a7 = tmpa[6];
		add.a8 = tmpa[7];
		add.a9 = tmpa[8];
		add.a10 = tmpa[9];
		add.a11 = tmpa[10];
		add.a12 = tmpa[11];
		add.a13 = tmpa[12];
		add.a14 = tmpa[13];
		add.a15 = tmpa[14];
		add.a16 = tmpa[15];

		return add;
	}

	/// <summary>
	/// Use the devices IPv6 loopback address
	/// </summary>
	/// 
	/// <returns>The IPv6 loopback address structure</returns>
	static const ipv6_address LoopBack()
	{
		ipv6_address add(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);

		return add;
	}

	/// <summary>
	/// Convert an address structure to a vector
	/// </summary>
	///
	/// <param name="Address">The IPv6 address structure</param>
	/// 
	/// <returns>The string representation of the address</returns>
	static std::vector<uint8_t> ToVector(const ipv6_address &Address)
	{
		std::vector<uint8_t> tmpa{ Address.a1, Address.a2, Address.a3, Address.a4, Address.a5, Address.a6, Address.a7, Address.a8, 
			Address.a9, Address.a10, Address.a11, Address.a12, Address.a13, Address.a14, Address.a15, Address.a16 };

		return tmpa;
	}

	/// <summary>
	/// Convert an address structure to a string
	/// </summary>
	///
	/// <param name="Address">The IPv6 address structure</param>
	/// 
	/// <returns>The string representation of the address</returns>
	static std::string ToString(const ipv6_address &Address)
	{
		const std::string DELIM = std::string(":");
		const std::string DEMRK = std::string("::");
		std::vector<uint8_t> tmpa;
		std::string tmps;
		size_t i;

		tmpa = ToVector(Address);

		for (i = 1; i < 16; i += 2)
		{
			if (tmpa[i - 1] == 0 && tmpa[i] == 0)
			{
				if (tmps.size() > 2 && tmps.substr(tmps.size() - 2, 2) != DEMRK)
				{
					tmps += DELIM;
				}
			}
			else
			{
				tmps += IntegerTools::IntToHex(tmpa[i - 1]) + IntegerTools::IntToHex(tmpa[i]);

				if (i < 14)
				{
					tmps += DELIM;
				}
			}
		}

		return tmps;
	}

} ipv6_address;

NAMESPACE_ROOTEND
#endif