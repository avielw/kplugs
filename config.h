/* this file should only have defines in it! */

#ifndef CONFIG
#define CONFIG

#define VERSION_MAJOR		(1)
#define VERSION_MINOR		(0)

#define MAX_RECUR			(20)
#define MAX_CALL_RECUR		(30)

#define CALL_STACK_SIZE		(30)
#define MAX_FUNC_NAME		(50)

#define MAX_STACK_FRAME (0x200)

#define STACK_MAX_PARAMETERS (15)

#ifdef DEBUG

#define DEBUG_PRINT(...) output_string(__VA_ARGS__)

#else

#define DEBUG_PRINT(format, ...) do {} while(0)

#endif

#ifdef __KERNEL__

/* will use the function kallsyms_lookup_name instead of find_symbol - works a lot better */ 
#define USE_KALLSYMS

#endif

#endif
