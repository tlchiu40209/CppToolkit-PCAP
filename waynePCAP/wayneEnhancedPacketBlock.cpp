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
			setInterfaceId((unsigned int)0);
			setTimestamp((unsigned long long)0);
			setPacketData("", 0, 0);

			updateBlockLength(structByteLength::EPB_INTERFACE_ID_LENGTH);
			updateBlockLength(structByteLength::EPB_TIMESTAMP_FULL_LENGTH);
			updateBlockLength(structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH);
			updateBlockLength(structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH);
		}

		EnhancedPacketBlock::EnhancedPacketBlock(unsigned int initInterfaceId, unsigned long long initTimestamp, unsigned int initCapturedPacketLength, unsigned int initOriginalPacketLength, char* packetData) {
			setBlockType(blockTypes::ENHANCED_PACKET);
			setInterfaceId(initInterfaceId);
			setTimestamp(initTimestamp);
			setPacketData(packetData, initCapturedPacketLength, initOriginalPacketLength);

			updateBlockLength(structByteLength::EPB_INTERFACE_ID_LENGTH);
			updateBlockLength(structByteLength::EPB_TIMESTAMP_FULL_LENGTH);
			updateBlockLength(structByteLength::EPB_CAPTURED_PACKET_LENGTH_LENGTH);
			updateBlockLength(structByteLength::EPB_ORIGINAL_PACKET_LENGTH_LENGTH);
			updateBlockLength(wayne::numberUtil::nextNearestMultOfXFromY(initCapturedPacketLength, (unsigned int)structByteLength::BLOCK_READ_UNIT));
		}

		EnhancedPacketBlock::~EnhancedPacketBlock() {
			delete[] this->interfaceId;
			delete[] this->timestampLower;
			delete[] this->timestampUpper;
			delete[] this->capturedPacketLength;
			delete[] this->originalPacketLength;
			delete[] this->packetData;
			for (auto const& [key, option] : this->options)
			{
				delete[] option;
			}
			this->options.clear();
		}

		EnhancedPacketBlock::EnhancedPacketBlock(const EnhancedPacketBlock &other) {
			setInterfaceIdExact(other.interfaceId);
			setTimestampUpperExact(other.timestampUpper);
			setTimestampLowerExact(other.timestampLower);
			setPacketData(other.packetData, wayne::numberUtil::bytesStaticToNumber(other.capturedPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER), wayne::numberUtil::bytesStaticToNumber(other.originalPacketLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER));
			for (auto const& [key, option] : other.options)
			{

			}
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
