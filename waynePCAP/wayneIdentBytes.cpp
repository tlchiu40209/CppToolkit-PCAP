/*
 * wayneIdentBytes.cpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#include "wayneIdentBytes.hpp"

namespace wayne {

	namespace PCAP
	{
		const char *identBytes::OPT_ENDOFOPT = "\x00\x00";
		const char *identBytes::OPT_COMMENT = "\x01\x00";
		const char *identBytes::SHB_HARDWARE = "\x02\x00";
		const char *identBytes::SHB_OS = "\x03\x00";
		const char *identBytes::SHB_USERAPPL = "\x04\x00";
		const char *identBytes::IDB_IF_NAME = "\x02\x00";
		const char *identBytes::IDB_IF_DESCRIPTION = "\x03\x00";
		const char *identBytes::IDB_IF_IPV4ADDR = "\x04\x00";
		const char *identBytes::IDB_IF_IPV6ADDR = "\x05\x00";
		const char *identBytes::IDB_IF_MACADDR = "\x06\00";
		const char *identBytes::IDB_IF_EUIADDR = "\x07\x00";
		const char *identBytes::IDB_IF_SPEED = "\x08\x00";
		const char *identBytes::IDB_IF_TSRESOL = "\x09\x00";
		const char *identBytes::IDB_IF_TZONE = "\x0a\x00";
		const char *identBytes::IDB_IF_FILTER = "\x0b\x00";
		const char *identBytes::IDB_IF_OS = "\x0c\x00";
		const char *identBytes::IDB_IF_FCSLEN = "\x0d\x00";
		const char *identBytes::IDB_IF_TSOFFSET = "\x0e\x00";
		const char *identBytes::IDB_IF_HARDWARE = "\x0f\x00";
		const char *identBytes::IDB_IF_TXSPEED = "\x10\x00";
		const char *identBytes::IDB_IF_RXSPEED = "\x11\x00";
		const char *identBytes::EPB_EPB_FLAGS = "\x02\x00";
		const char *identBytes::EPB_EPB_HASH = "\x03\x00";
		const char *identBytes::EPB_EPB_DROPCOUNT = "\x04\x00";
		const char *identBytes::NBR_NS_DNSNAME = "\x02\x00";
		const char *identBytes::NBR_NS_DNSIP4ADDR = "\x03\x00";
		const char *identBytes::NBR_NS_DNSIP6ADDR = "\x04\x00";
		const char *identBytes::ISB_ISB_STARTTIME = "\x02\x00";
		const char *identBytes::ISB_ISB_ENDTIME = "\x03\x00";
		const char *identBytes::ISB_ISB_IFRECV = "\x04\x00";
		const char *identBytes::ISB_ISB_IFDROP = "\x05\x00";
		const char *identBytes::ISB_ISB_FILTERACCEPT = "\x06\x00";
		const char *identBytes::ISB_ISB_OSDROP = "\x07\x00";
		const char *identBytes::ISB_ISB_USRDELIV = "\x08\x00";
	}

} /* namespace wayne */
