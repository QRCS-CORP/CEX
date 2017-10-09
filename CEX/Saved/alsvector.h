#ifndef _CEX_ALSVECTOR_H
#define _CEX_ALSVECTOR_H

#include "CexDomain.h"
#include "Intrinsics.h"
#include <iostream>
#include <type_traits>
#include <string>

NAMESPACE_COMMON

// TODO: just an example of pod!
template<class T, std::size_t N>
class alsvector
{
	// properly aligned uninitialized storage for N T's
	typename std::aligned_storage<sizeof(T), alignof(T)>::type data[N];
	std::size_t m_size = 0;

public:
	// Create an object in aligned storage
	template<typename ...Args> void emplace_back(Args&&... args)
	{
		if (m_size >= N) // possible error handling
			throw std::bad_alloc{};
		new(data + m_size) T(std::forward<Args>(args)...);
		++m_size;
	}

	// Access an object in aligned storage
	const T& operator[](std::size_t pos) const
	{
		return *reinterpret_cast<const T*>(data + pos);
	}

	// Delete objects from aligned storage
	~alsvector()
	{
		for (std::size_t pos = 0; pos < m_size; ++pos)
			reinterpret_cast<T*>(data + pos)->~T();
	}
};

NAMESPACE_COMMONEND
#endif