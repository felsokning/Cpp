
#include "stdafx.h"

// Bit-length matters.
#if _WIN64
	using size_t = UINT64;
#else
	using size_t = UINT32;
#endif

std::size_t ReturnSizeT = 0;

std::size_t GetWeekNumber()
{
	char buffer[64];
	time_t null_time = time(nullptr);
	time_t * null_p_time = &null_time;
	struct tm buf = tm();
	if (gmtime_s(&buf, null_p_time) == NO_ERROR)
	{
		const size_t return_value = strftime(buffer, sizeof(buffer), "%W", &buf);
		return return_value;
	}
	else
	{
		return size_t(100);
	}
}

extern "C"
{
	__declspec(dllexport) std::size_t VeckanEntry()
	{
		ReturnSizeT = 0;
		ReturnSizeT = GetWeekNumber();
		return ReturnSizeT;
	}

}