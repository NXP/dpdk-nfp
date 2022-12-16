
#include <string.h>

enum log_level_s {
        LOG_DISABLED = 0,
        LOG_ERROR,
        LOG_WARNING,
        LOG_INFO,
        LOG_DEBUG,
        LOG_MAX_LEVEL
};

enum log_level_s loglevel;

#define __FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define _ECAT_LOG(level, fmt, ...) do {                         \
	loglevel = LOG_DEBUG; \
	if (level > loglevel)                               \
	break;							\
	fprintf(stderr, "[%s %s:%d] " fmt "\n",            	    \
			(level == LOG_ERROR)   ? "E" :              \
			(level == LOG_WARNING) ? "W" :              \
			(level == LOG_INFO)    ? "I" :              \
			(level == LOG_DEBUG)   ? "D" : "?",         \
			__FILENAME__, __LINE__,                     \
			##__VA_ARGS__);                             \
} while (0)

//#define ECAT_DEBUG
#if defined(ECAT_DEBUG)
#define ECAT_DBG(fmt, ...) \
        _ECAT_LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#else
#define ECAT_DBG(fmt, ...) do {} while (0)
#endif
