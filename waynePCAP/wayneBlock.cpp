/*
 * wayneBlock.cpp
 *
 *  Created on: 2023年10月10日
 *      Author: weich
 */

#include "wayneBlock.hpp"

namespace wayne {
	namespace PCAP {

		block::block() {
			setBlockType(blockTypes::ENHANCED_PACKET);
			setBlockLength(0);
			updateBlockLength(structByteLength::BLOCK_TYPE_LENGTH + structByteLength::BLOCK_LENGTH_LENGTH + structByteLength::BLOCK_LENGTH_LENGTH);
			/*BlockType took 4 bytes, BlockLength took 8 bytes.*/
		}

		block::block(blockTypes type) {
			setBlockType(type);
			setBlockLength(0);
			updateBlockLength(structByteLength::BLOCK_TYPE_LENGTH + structByteLength::BLOCK_LENGTH_LENGTH + structByteLength::BLOCK_LENGTH_LENGTH);
			/*BlockType took 4 bytes, BlockLength took 8 bytes.*/
		}

		block::~block() {
			delete[] this->blockType;
			delete[] this->blockLength;
		}

		block::block(const block &other) { /*Copy constructor*/
			setBlockTypeExact(other.blockType);
			setBlockLengthExact(other.blockLength);
		}

		block::block(block &&other) { /*Move Constructor*/
			this->blockType = other.blockType;
			this->blockLength = other.blockLength;
			other.blockType = nullptr;
			other.blockLength = nullptr;
			/* Move the pointer to other item, and the temp "other" item will be freed.*/
		}

		block& block::operator=(const block &other) { /*Copy Assign Constructor*/
			if (this != &other)
			{
				setBlockTypeExact(other.blockType);
				setBlockLengthExact(other.blockLength);
			}
			return *this;
		}

		block& block::operator=(block &&other) { /*Move Assign constructor*/
			if (this != &other)
			{
				this->blockType = other.blockType;
				this->blockLength = other.blockLength;
				other.blockType = nullptr;
				other.blockLength = nullptr;
			}
			return *this;
		}

		bool block::operator==(const block &other)
		{
			if (numberUtil::bytesStaticToNumber(this->blockType, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != numberUtil::bytesStaticToNumber(this->blockType, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT))
			{
				return false;
			}
			if (numberUtil::bytesStaticToNumber(this->blockLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != numberUtil::bytesStaticToNumber(this->blockLength, numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT))
			{
				return false;
			}
			return true;
		}

		void block::setBlockType(blockTypes type)
		{
			delete[] this->blockType;
			this->blockType = numberUtil::numberToBytesStatic((int)type, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		void block::setBlockTypeExact(char* newBlockType)
		{
			delete[] this->blockType;
			this->blockType = new char[structByteLength::BLOCK_TYPE_LENGTH];
			std::copy(newBlockType, newBlockType + structByteLength::BLOCK_TYPE_LENGTH, this->blockType);
		}

		blockTypes block::getBlockType()
		{
			return (blockTypes)(numberUtil::bytesStaticToNumber(this->blockType, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT));
		}

		char* block::getBlockTypeExact()
		{
			char* toReturn = new char[structByteLength::BLOCK_TYPE_LENGTH];
			std::copy(this->blockType, this->blockType + structByteLength::BLOCK_LENGTH_LENGTH, toReturn);
			return toReturn;
		}

		int block::getBlockLength()
		{
			return numberUtil::bytesStaticToNumber(this->blockLength, numberUtil::numberTypeReference::DATA_TYPE_INTEGER, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		char* block::getBlockLengthExact()
		{
			char* toReturn = new char[std::strlen(this->blockLength)];
			std::copy(this->blockLength, this->blockLength + structByteLength::BLOCK_LENGTH_LENGTH, toReturn);
			return toReturn;
		}

		bool block::updateBlockLength(int deltaLength)
		{
			if (deltaLength % 4 != 0)
			{
				wayne::IO::logLn("PCAPNG only allows size update with the size of 4.", true);
				return false;
			}
			unsigned int blockLengthRecovered = numberUtil::bytesStaticToNumber(this->blockLength, blockLengthRecovered, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
			delete this->blockLength;
			if (blockLengthRecovered + deltaLength < 0) {
				this->blockLength = numberUtil::numberToBytesStatic((unsigned int)0, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
				return false;
			} else {
				blockLengthRecovered += deltaLength;
				this->blockLength = numberUtil::numberToBytesStatic(blockLengthRecovered, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
				return true;
			}
		}

		bool block::updateBlockLengthExact(const char* deltaLengthExact)
		{
			int deltaLengthRecovered = numberUtil::bytesStaticToNumber(const_cast<char*>(deltaLengthExact), deltaLengthRecovered, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
			return updateBlockLength(deltaLengthRecovered);
		}

		void block::setBlockLength(unsigned int exactLength)
		{
			delete[] this->blockLength;
			this->blockLength = numberUtil::numberToBytesStatic(exactLength, numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);

		}

		void block::setBlockLengthExact(const char* exactLengthExact)
		{
			delete[] this->blockLength;
			this->blockLength = new char[structByteLength::BLOCK_LENGTH_LENGTH];
			std::copy(exactLengthExact, exactLengthExact + structByteLength::BLOCK_LENGTH_LENGTH, this->blockLength);
		}

	} /* namespace PCAP */
} /* namespace wayne */
