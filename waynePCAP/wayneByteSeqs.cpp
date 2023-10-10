/*
 * wayneByteSeqs.cpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#include "wayneByteSeqs.hpp"

namespace wayne {

	namespace PCAP
	{
		const char *byteSeqs::BYTE_ORDER_BIG_ENDIAN = "\x1a\x2b\x3c\x4d";
		const char *byteSeqs::BYTE_ORDER_SMALL_ENDIAN = "\x4d\x3c\x2b\x1a";
		const char *byteSeqs::BLOCK_TYPE_SECTION_HEADER = "\x0a\x0d\x0d\x0a";
		const char *byteSeqs::BLOCK_TYPE_INTERFACE_DESCRIPTION = "\x00\x00\x00\x01";
		const char *byteSeqs::BLOCK_TYPE_PACKET = "\x00\x00\x00\x02";
		const char *byteSeqs::BLOCK_TYPE_ENHANCED_PACKET = "\x00\x00\x00\x06";
		const char *byteSeqs::BLOCK_TYPE_SIMPLE_PACKET = "\x00\x00\x00\x03";
		const char *byteSeqs::BLOCK_TYPE_NAME_RESOLUTION = "\x00\x00\x00\x04";
		const char *byteSeqs::BLOCK_TYPE_INTERFACE_STATISTICS = "\x00\x00\x00\x05";
		const char *byteSeqs::BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT = "\x00\x00\x00\x09";
		const char *byteSeqs::BLOCK_TYPE_DECRYPTION_SECRETS = "\x00\x00\x00\x0a";
		const char *byteSeqs::BLOCK_TYPE_CUSTOM = "\x00\x00\x0b\xad";
		const char *byteSeqs::BLOCK_TYPE_CUSTOM_CONST = "\x40\x00\x0b\xad";
	}

} /* namespace wayne */
