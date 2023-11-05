/*
 * wayneEnhancedPacketBlock.cpp
 *
 *  Created on: 2023年11月5日
 *      Author: weich
 */

#include "wayneEnhancedPacketBlock.hpp"

namespace wayne {
	namespace PCAP {

		EnhancedPacketBlock::EnhancedPacketBlock() {
			setBlockType(blockTypes::ENHANCED_PACKET);
			

		}

		EnhancedPacketBlock::EnhancedPacketBlock(unsigned int initInterfaceId, unsigned int initTimestampUpper, unsigned int initTimestampLower, unsigned int initCapturedPacketLength, unsigned int initOriginalPacketLength, char* packetData) {
			setBlockType(blockTypes::ENHANCED_PACKET);
			

		}

		EnhancedPacketBlock::~EnhancedPacketBlock() {
			// TODO Auto-generated destructor stub
		}

		EnhancedPacketBlock::EnhancedPacketBlock(const EnhancedPacketBlock &other) {
			// TODO Auto-generated constructor stub

		}

		EnhancedPacketBlock::EnhancedPacketBlock(EnhancedPacketBlock &&other) {
			// TODO Auto-generated constructor stub

		}

		EnhancedPacketBlock& EnhancedPacketBlock::operator=(
				const EnhancedPacketBlock &other) {
			// TODO Auto-generated method stub

		}

		EnhancedPacketBlock& EnhancedPacketBlock::operator=(
				EnhancedPacketBlock &&other) {
			// TODO Auto-generated method stub

		}

	} /* namespace PCAP */
} /* namespace wayne */
