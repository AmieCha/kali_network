# FindPCAP.cmake
# Locates libpcap and defines:
#   PCAP_FOUND
#   PCAP_INCLUDE_DIR
#   PCAP_LIBRARIES

find_path(PCAP_INCLUDE_DIR NAMES pcap.h pcap/pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR
)

if(PCAP_FOUND)
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)