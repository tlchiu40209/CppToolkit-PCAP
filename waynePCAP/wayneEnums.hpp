/*
 * wayneSectionHeaderBlock.hpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_WAYNEENUMS_HPP_
#define LIB_WAYNEPCAP_WAYNEENUMS_HPP_

namespace wayne {
	namespace PCAP {
		enum blockTypes
		{
			SECTION_HEADER,
			INTERFACE_DESCRIPTION,
			ENHANCED_PACKET,
			SIMPLE_PACKET,
			PACKET,
			NAME_RESOLUTION,
			INTERFACE_STATISTICS,
			SYSTEMD_JOURNAL_EXPORT,
			DECRYPTION_SECRETS,
			CUSTOM,
			CUSTOM_CONST
		};

		enum endianTypes
		{
			BIG,
			SMALL
		};

		enum optionTypes
		{
			SHB_HARDWARE,
			SHB_OS,
			SHB_USERAPPL
		};
	}
}

#endif /* LIB_WAYNEPCAP_WAYNEENUMS_HPP_ */
