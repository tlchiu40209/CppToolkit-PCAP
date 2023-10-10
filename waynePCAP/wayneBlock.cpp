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
			this->blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_ENHANCED_PACKET)];
			std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_ENHANCED_PACKET, std::strlen(byteSeqs::BLOCK_TYPE_ENHANCED_PACKET));
			this->blockLength = new char[]{"\x00"};
		}

		block::~block() {
			delete[] this->blockType;
			delete[] this->blockLength;
		}

		block::block(const block &other) { /*Copy constructor*/
			this->blockType = new char[std::strlen(other.blockType)];
			std::strncpy(this->blockType, other.blockType, std::strlen(other.blockType));
			this->blockLength = new char[std::strlen(other.blockLength)];
			std::strncpy(this->blockLength, other.blockLength, std::strlen(other.blockLength));
		}

		block::block(block &&other) { /*Move Constructor*/
			this->blockType = new char[std::strlen(other.blockType)];
			std::strncpy(this->blockType, other.blockType, std::strlen(other.blockType));
			this->blockLength = new char[std::strlen(other.blockLength)];
			std::strncpy(this->blockLength, other.blockLength, std::strlen(other.blockLength));

			delete[] other.blockType;
			delete[] other.blockLength;
		}

		block& block::operator=(const block &other) { /*Copy Assign Constructor*/
			if (this != &other)
			{
				delete[] this->blockType;
				this->blockType = new char[std::strlen(other.blockType)];
				std::strncpy(this->blockType, other.blockType, std::strlen(other.blockType));
				delete[] this->blockLength;
				this->blockLength = new char[std::strlen(other.blockLength)];
				std::strncpy(this->blockLength, other.blockLength, std::strlen(other.blockLength));
			}
			return *this;
		}

		block& block::operator=(block &&other) { /*Move Assign constructor*/
			if (this != &other)
			{
				delete[] this->blockType;
				this->blockType = new char[std::strlen(other.blockType)];
				std::strncpy(this->blockType, other.blockType, std::strlen(other.blockType));
				delete[] this->blockLength;
				this->blockLength = new char[std::strlen(other.blockLength)];
				std::strncpy(this->blockLength, other.blockLength, std::strlen(other.blockLength));

				delete[] other.blockType;
				delete[] other.blockLength;
			}
			return *this;
		}

		void block::setBlockType(char* newBlockType)
		{
			delete[] this->blockType;
			this->blockType = new char[std::strlen(newBlockType)];
			std::strncpy(this->blockType, newBlockType, std::strlen(newBlockType));
		}

		void block::setBlockType(blockTypes type)
		{
			switch (type)
            {
				case blockTypes::CUSTOM:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_CUSTOM)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_CUSTOM, std::strlen(byteSeqs::BLOCK_TYPE_CUSTOM));
					break;
				}
				case blockTypes::CUSTOM_CONST:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_CUSTOM_CONST)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_CUSTOM_CONST, std::strlen(byteSeqs::BLOCK_TYPE_CUSTOM_CONST));
					break;
				}

				case blockTypes::DECRYPTION_SECRETS:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_DECRYPTION_SECRETS)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_DECRYPTION_SECRETS, std::strlen(byteSeqs::BLOCK_TYPE_DECRYPTION_SECRETS));
					break;
				}

				case blockTypes::ENHANCED_PACKET:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_ENHANCED_PACKET)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_ENHANCED_PACKET, std::strlen(byteSeqs::BLOCK_TYPE_ENHANCED_PACKET));
					break;
				}

				case blockTypes::INTERFACE_DESCRIPTION:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_INTERFACE_DESCRIPTION)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_INTERFACE_DESCRIPTION, std::strlen(byteSeqs::BLOCK_TYPE_INTERFACE_DESCRIPTION));
					break;
				}

				case blockTypes::INTERFACE_STATISTICS:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_INTERFACE_STATISTICS)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_INTERFACE_STATISTICS, std::strlen(byteSeqs::BLOCK_TYPE_INTERFACE_STATISTICS));
					break;
				}

				case blockTypes::NAME_RESOLUTION:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_NAME_RESOLUTION)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_NAME_RESOLUTION, std::strlen(byteSeqs::BLOCK_TYPE_NAME_RESOLUTION));
					break;
				}

				case blockTypes::PACKET:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_PACKET)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_PACKET, std::strlen(byteSeqs::BLOCK_TYPE_PACKET));
					break;
				}

				case blockTypes::SECTION_HEADER:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_SECTION_HEADER)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_SECTION_HEADER, std::strlen(byteSeqs::BLOCK_TYPE_SECTION_HEADER));
					break;
				}

				case blockTypes::SIMPLE_PACKET:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_SIMPLE_PACKET)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_SIMPLE_PACKET, std::strlen(byteSeqs::BLOCK_TYPE_SIMPLE_PACKET));
					break;
				}

				case blockTypes::SYSTEMD_JOURNAL_EXPORT:
				{
					blockType = new char[std::strlen(byteSeqs::BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT)];
					std::strncpy(this->blockType, byteSeqs::BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT, std::strlen(byteSeqs::BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT));
					break;
				}
            }
		}

		blockTypes block::getBlockType()
		{
			if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_CUSTOM) == 0)
			{
					return blockTypes::CUSTOM;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_CUSTOM_CONST) == 0)
			{
					return blockTypes::CUSTOM_CONST;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_DECRYPTION_SECRETS)== 0)
			{
					return blockTypes::DECRYPTION_SECRETS;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_ENHANCED_PACKET) == 0)
			{
					return blockTypes::ENHANCED_PACKET;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_INTERFACE_DESCRIPTION) == 0)
			{
					return blockTypes::INTERFACE_DESCRIPTION;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_INTERFACE_STATISTICS) == 0)
			{
					return blockTypes::INTERFACE_STATISTICS;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_NAME_RESOLUTION) == 0)
			{
					return blockTypes::NAME_RESOLUTION;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_PACKET) == 0)
			{
					return blockTypes::PACKET;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_SECTION_HEADER) == 0)
			{
					return blockTypes::SECTION_HEADER;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_SIMPLE_PACKET) == 0)
			{
					return blockTypes::SIMPLE_PACKET;
			}
			else if (std::strcmp(this->blockType, byteSeqs::BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT) == 0)
			{
					return blockTypes::SYSTEMD_JOURNAL_EXPORT;
			}
			else
			{
					return blockTypes::CUSTOM;
			}
		}

		char* block::getBlockTypeExact()
		{
			char* toReturn = new char[std::strlen(this->blockType)];
			std::strncpy(toReturn, this->blockType, std::strlen(this->blockType));
			return toReturn;
		}

		size_t block::getBlockLength()
		{
			return (size_t)((unsigned int)std::strtol(blockLength, NULL, 16));
		}

		char* block::getBlockLengthExact()
		{
			char* toReturn = new char[std::strlen(this->blockLength)];
			std::strncpy(toReturn, this->blockLength, std::strlen(this->blockLength));
			return toReturn;
		}
	} /* namespace PCAP */
} /* namespace wayne */
