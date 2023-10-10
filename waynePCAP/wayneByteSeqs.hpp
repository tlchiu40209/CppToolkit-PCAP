/*
 * wayneByteSeqs.hpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNEBYTESEQS_HPP_
#define LIB_WAYNEPCAP_WAYNEBYTESEQS_HPP_

namespace wayne {

	namespace PCAP
	{
		class byteSeqs
		{
			public:
				static const char *BYTE_ORDER_BIG_ENDIAN;
				static const char *BYTE_ORDER_SMALL_ENDIAN;
				static const char *BLOCK_TYPE_SECTION_HEADER;
				static const char *BLOCK_TYPE_INTERFACE_DESCRIPTION;
				static const char *BLOCK_TYPE_PACKET;
				static const char *BLOCK_TYPE_ENHANCED_PACKET;
				static const char *BLOCK_TYPE_SIMPLE_PACKET;
				static const char *BLOCK_TYPE_NAME_RESOLUTION;
				static const char *BLOCK_TYPE_INTERFACE_STATISTICS;
				static const char *BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT;
				static const char *BLOCK_TYPE_DECRYPTION_SECRETS;
				static const char *BLOCK_TYPE_CUSTOM;
				static const char *BLOCK_TYPE_CUSTOM_CONST;
		};
	}

} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_WAYNEBYTESEQS_HPP_ */
