#include "ParallelTools.h"

#if defined(CEX_HAS_OPENMP)
#	include <omp.h>
#else
#	include <future>
#endif

NAMESPACE_TOOLS

size_t ParallelTools::ProcessorCount()
{
#if defined(CEX_HAS_OPENMP)
	return static_cast<size_t>(omp_get_num_procs());
#else
	return static_cast<size_t>(std::thread::hardware_concurrency());
#endif
}

void ParallelTools::ParallelFor(size_t From, size_t To, const std::function<void(size_t)> &F)
{
#if defined(CEX_HAS_OPENMP)
#	pragma omp parallel num_threads(static_cast<int32_t>(To))
	{
		size_t i = From + static_cast<size_t>(omp_get_thread_num());
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
	{
		futures[i].wait();
	}

	futures.clear();
#endif
}

void ParallelTools::ParallelTask(const std::function<void()> &F)
{
#if defined(CEX_HAS_OPENMP)
#	pragma omp parallel
	{
#		pragma omp single nowait
		{
			F();
		}
	}
#else
	std::future<void> fut = std::async(std::launch::async, [F]()
	{
		F();
	});

	fut.get();
#endif
}

void ParallelTools::Vectorize(const std::function<void()> &F)
{
#if defined(CEX_OPENMP_VERSION_30)
#	pragma omp simd
	F();
#else
	F();
#endif
}

NAMESPACE_TOOLSEND
