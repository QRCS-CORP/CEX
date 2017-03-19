#include "ParallelUtils.h"
#include <functional>

#if defined(_OPENMP)
#	include <omp.h>
#else
#	include <future>
#endif

NAMESPACE_UTILITY

size_t ParallelUtils::ProcessorCount()
{
#if defined(_OPENMP)
	return static_cast<size_t>(omp_get_num_procs());
#else
	return static_cast<size_t>(std::thread::hardware_concurrency());
#endif
}

void ParallelUtils::ParallelFor(size_t From, size_t To, const std::function<void(size_t)> &F)
{
#if defined(_OPENMP)
#pragma omp parallel num_threads((int)To)
	{
		size_t i = (size_t)omp_get_thread_num();
		F(i);
	}
#else
	std::vector<std::future<void>> futures;

	for (size_t i = From; i < To; ++i)
	{
		auto fut = std::async([i, F]()
		{
			F(i);
		});
		futures.push_back(std::move(fut));
	}

	for (size_t i = 0; i < futures.size(); ++i)
		futures[i].wait();

	futures.clear();
#endif
}

NAMESPACE_UTILITYEND