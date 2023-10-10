/*
 * wayneIdentBytes.hpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNEIDENTBYTES_HPP_
#define LIB_WAYNEPCAP_WAYNEIDENTBYTES_HPP_

namespace wayne {

	namespace PCAP
	{
		class identBytes
		{
			public:
				static const char *OPT_ENDOFOPT;
				static const char *OPT_COMMENT;
				static const char *SHB_HARDWARE;
				static const char *SHB_OS;
				static const char *SHB_USERAPPL;
				static const char *IDB_IF_NAME;
				static const char *IDB_IF_DESCRIPTION;
				static const char *IDB_IF_IPV4ADDR;
				static const char *IDB_IF_IPV6ADDR;
				static const char *IDB_IF_MACADDR;
				static const char *IDB_IF_EUIADDR;
				static const char *IDB_IF_SPEED;
				static const char *IDB_IF_TSRESOL;
				static const char *IDB_IF_TZONE;
				static const char *IDB_IF_FILTER;
				static const char *IDB_IF_OS;
				static const char *IDB_IF_FCSLEN;
				static const char *IDB_IF_TSOFFSET;
				static const char *IDB_IF_HARDWARE;
				static const char *IDB_IF_TXSPEED;
				static const char *IDB_IF_RXSPEED;
				static const char *EPB_EPB_FLAGS;
				static const char *EPB_EPB_HASH;
				static const char *EPB_EPB_DROPCOUNT;
				static const char *NBR_NS_DNSNAME;
				static const char *NBR_NS_DNSIP4ADDR;
				static const char *NBR_NS_DNSIP6ADDR;
				static const char *ISB_ISB_STARTTIME;
				static const char *ISB_ISB_ENDTIME;
				static const char *ISB_ISB_IFRECV;
				static const char *ISB_ISB_IFDROP;
				static const char *ISB_ISB_FILTERACCEPT;
				static const char *ISB_ISB_OSDROP;
				static const char *ISB_ISB_USRDELIV;
		};
	}

} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEIDENTBYTES_HPP_ */
