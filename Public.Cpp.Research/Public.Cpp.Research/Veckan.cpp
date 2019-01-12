
#include "stdafx.h"

// Bitness matters.
#if _WIN64
	using size_t = UINT64;
#else
	using size_t = UINT32;
#endif

std::size_t ReturnSizeT = 0;

std::size_t GetWeekNumber()
{
	char timebuf[64];
	time_t nulltime = time(NULL);
	time_t * nullptime = &nulltime;
	struct tm buf = tm();
	if (gmtime_s(&buf, nullptime) == NO_ERROR)
	{
		size_t returnValue = strftime(timebuf, sizeof(timebuf), "%W", &buf);
		return returnValue;
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