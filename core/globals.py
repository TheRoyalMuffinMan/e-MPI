# Defined Globals
CPU_INFO = "/proc/cpuinfo"
FREQUENCY_AMD_LOCATION = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies"
FREQUENCY_MAX_INTEL_LOCATION = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"
FREQUENCY_MIN_INTEL_LOCATION = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq"
DEFAULT_DURATION = 75
DEFAULT_EBPF_PATH = "../ebpf/kernel.c"
DEFAULT_OUTPUT_FILE = "output.log"
FREQ_LOWERED = 0

# Undefined Globals
PHYSICAL_CORES = None
LOGICAL_CORES = None
THREADS_PER_CORE = None
CPU_SOCKETS = None
MANUFACTURER = None
CPU_FREQUENCY_RANGE = None
