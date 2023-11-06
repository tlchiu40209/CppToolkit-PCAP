/*
 * wayneInterfaceDescriptionBlock.cpp
 *
 *  Created on: 2023年10月18日
 *      Author: weich
 */

/* Important Note:
 * Although according to IETF's SPEC, PCAPNG should supports
 * multiple IPv4 and IPv6 addresses, but it makes implementation
 * unreasonable for current time schedule.
 * This release only supports 1 IPv4 and 1 IPv6
 * */

#include "wayneInterfaceDescriptionBlock.hpp"

namespace wayne {
	namespace PCAP {

		interfaceDescriptionBlock::interfaceDescriptionBlock() 
		{
			setBlockType(blockTypes::INTERFACE_DESCRIPTION);
			setLinkType(linkTypes::LINKTYPE_ETHERNET);
			this->reserved = wayne::numberUtil::numberToBytesStatic((short)structByteDefault::IDB_RESERVED_VALUE, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
			setSnapLength((unsigned int)structByteDefault::IDB_SNAP_LENGTH_VALUE);

			updateBlockLength(structByteLength::IDB_LINK_TYPE_LENGTH + structByteLength::IDB_RESERVED_LENGTH);
			updateBlockLength(structByteLength::IDB_SNAP_LENGTH_LENGTH);
		}

		interfaceDescriptionBlock::interfaceDescriptionBlock(linkTypes initType, unsigned int initSnapLength) 
		{
			setBlockType(blockTypes::INTERFACE_DESCRIPTION);
			setLinkType(initType);
			this->reserved = wayne::numberUtil::numberToBytesStatic((short)structByteDefault::IDB_RESERVED_VALUE, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
			setSnapLength(initSnapLength);
			updateBlockLength(structByteLength::IDB_LINK_TYPE_LENGTH + structByteLength::IDB_RESERVED_LENGTH);
			updateBlockLength(structByteLength::IDB_SNAP_LENGTH_LENGTH);
		}

		interfaceDescriptionBlock::~interfaceDescriptionBlock() {
			delete[] this->linkType;
			delete[] this->reserved;
			delete[] this->snapLength;
			for (auto const& [key, option] : this->options)
			{
				delete[] option;

			}
			options.clear();
		}

		interfaceDescriptionBlock::interfaceDescriptionBlock(const interfaceDescriptionBlock &other) 
		{
			setLinkTypeExact(other.linkType);
			delete this->reserved;
			this->reserved = new char[(int)wayne::numberUtil::bytesStaticToNumber(other.reserved, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)];
			std::copy(other.reserved, other.reserved + structByteLength::IDB_RESERVED_LENGTH, this->reserved);
			setSnapLengthExact(other.snapLength);

			this->multCounts.clear();
			for (auto const& [key, option] : other.multCounts)
			{
				this->multCounts[key] = option;
			}

			this->options.clear();
			for (auto const& [key, option] : other.options)
			{
				int optionLength = 0;
				if (isDynamicLengthOption(key))
				{
					optionLength = std::strlen(option);
				}
				else
				{
					if (isStaticLengthOptionAllowsMultiple(key))
					{
						switch (key)
						{
							case optionTypes::IF_IPV4ADDR:
								optionLength = (isOptionCurrentlyMultiple(key)) ? optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key) : optionByteLength::IF_IPV4ADDR_LENGTH;
								break;
							case optionTypes::IF_IPV6ADDR:
								optionLength = (isOptionCurrentlyMultiple(key)) ? optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key) : optionByteLength::IF_IPV6ADDR_LENGTH;
								break;
							default:
								break;
						}
					}
					else
					{
						switch (key)
						{
						case optionTypes::IF_MACADDR:
							optionLength = optionByteLength::IF_MACADDR_LENGTH;
							break;
						case optionTypes::IF_EUIADDR:
							optionLength = optionByteLength::IF_EUIADDR_LENGTH;
							break;
						case optionTypes::IF_SPEED:
							optionLength = optionByteLength::IF_SPEED_LENGTH;
							break;
						case optionTypes::IF_TSRESOL:
							optionLength = optionByteLength::IF_TSRESOL_LENGTH;
							break;
						case optionTypes::IF_TZONE:
							optionLength = optionByteLength::IF_TZONE_LENGTH;
							break;
						case optionTypes::IF_FCSLEN:
							optionLength = optionByteLength::IF_FCSLEN_LENGTH;
							break;
						case optionTypes::IF_TSOFFSET:
							optionLength = optionByteLength::IF_TSOFFSET_LENGTH;
							break;
						case optionTypes::IF_TXSPEED:
							optionLength = optionByteLength::IF_TXSPEED_LENGTH;
							break;
						case optionTypes::IF_RXSPEED:
							optionLength = optionByteLength::IF_RXSPEED_LENGTH;
							break;
						default:
							break;
							//Don't do anything.
						}
					}
				}
				this->options[key] = new char[optionLength];
				std::copy(option, option + optionLength, this->options[key]);
			}
		}

		interfaceDescriptionBlock::interfaceDescriptionBlock(interfaceDescriptionBlock &&other) 
		{
			this->linkType = other.linkType;
			this->reserved = other.reserved;
			this->snapLength = other.snapLength;
			other.linkType = nullptr;
			other.reserved = nullptr;
			other.snapLength = nullptr;

			this->multCounts.clear();
			for (auto const& [key, option] : other.multCounts)
			{
				this->multCounts[key] = option;
				other.multCounts[key] = (unsigned int)0;
			}

			this->options.clear();
			for (auto const& [key, option] : other.options)
			{
				this->options[key] = option;
				other.options[key] = nullptr;
			}

		}

		interfaceDescriptionBlock& interfaceDescriptionBlock::operator=(const interfaceDescriptionBlock &other)
		{
			if (this != &other)
			{
				setLinkTypeExact(other.linkType);
				delete this->reserved;
				this->reserved = new char[(int)wayne::numberUtil::bytesStaticToNumber(other.reserved, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)];
				std::copy(other.reserved, other.reserved + structByteLength::IDB_RESERVED_LENGTH, this->reserved);
				setSnapLengthExact(other.snapLength);

				this->multCounts.clear();
				for (auto const& [key, option] : other.multCounts)
				{
					this->multCounts[key] = option;
				}

				this->options.clear();
				for (auto const& [key, option] : other.options)
				{
					int optionLength = 0;
					if (isDynamicLengthOption(key))
					{
						optionLength = std::strlen(option);
					}
					else
					{
						if (isStaticLengthOptionAllowsMultiple(key))
						{
							switch (key)
							{
								case optionTypes::IF_IPV4ADDR:
									optionLength = (isOptionCurrentlyMultiple(key)) ? optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key) : optionByteLength::IF_IPV4ADDR_LENGTH;
									break;
								case optionTypes::IF_IPV6ADDR:
									optionLength = (isOptionCurrentlyMultiple(key)) ? optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key) : optionByteLength::IF_IPV6ADDR_LENGTH;
									break;
								default:
									break;
							}
						}
						else
						{
							switch (key)
							{
							case optionTypes::IF_MACADDR:
								optionLength = optionByteLength::IF_MACADDR_LENGTH;
								break;
							case optionTypes::IF_EUIADDR:
								optionLength = optionByteLength::IF_EUIADDR_LENGTH;
								break;
							case optionTypes::IF_SPEED:
								optionLength = optionByteLength::IF_SPEED_LENGTH;
								break;
							case optionTypes::IF_TSRESOL:
								optionLength = optionByteLength::IF_TSRESOL_LENGTH;
								break;
							case optionTypes::IF_TZONE:
								optionLength = optionByteLength::IF_TZONE_LENGTH;
								break;
							case optionTypes::IF_FCSLEN:
								optionLength = optionByteLength::IF_FCSLEN_LENGTH;
								break;
							case optionTypes::IF_TSOFFSET:
								optionLength = optionByteLength::IF_TSOFFSET_LENGTH;
								break;
							case optionTypes::IF_TXSPEED:
								optionLength = optionByteLength::IF_TXSPEED_LENGTH;
								break;
							case optionTypes::IF_RXSPEED:
								optionLength = optionByteLength::IF_RXSPEED_LENGTH;
								break;
							default:
								break;
								//Don't do anything.
							}
						}
					}
					this->options[key] = new char[optionLength];
					std::copy(option, option + optionLength, this->options[key]);
				}
			}
			return *this;
		}

		interfaceDescriptionBlock& interfaceDescriptionBlock::operator=(interfaceDescriptionBlock &&other)
		{
			if (this != &other)
			{
				this->linkType = other.linkType;
				this->reserved = other.reserved;
				this->snapLength = other.snapLength;
				other.linkType = nullptr;
				other.reserved = nullptr;
				other.snapLength = nullptr;

				this->multCounts.clear();
				for (auto const& [key, option] : other.multCounts)
				{
					this->multCounts[key] = option;
					other.multCounts[key] = (unsigned int)0;
				}

				this->options.clear();
				for (auto const& [key, option] : other.options)
				{
					this->options[key] = option;
					other.options[key] = nullptr;
				}
			}
			return *this;
		}

		bool interfaceDescriptionBlock::operator==(const interfaceDescriptionBlock &other)
		{
			if (wayne::numberUtil::bytesStaticToNumber(this->linkType, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != (wayne::numberUtil::bytesStaticToNumber(other.linkType, wayne::numberUtil::numberTypeReference::DATA_TYPE_SHORT, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)))
			{
				return false;
			}
			if (wayne::numberUtil::bytesStaticToNumber(this->linkType, wayne::numberUtil::numberTypeReference::DATA_TYPE_INTEGER, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT) != (wayne::numberUtil::bytesStaticToNumber(other.linkType, wayne::numberUtil::numberTypeReference::DATA_TYPE_INTEGER, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT)))
			{
				return false;
			}
			for (auto const& [key, option] : other.options)
			{
				if (std::strcmp(this->options[key], option) != 0)
				{
					return false;
				}
			}
			return true;
		}

		linkTypes interfaceDescriptionBlock::getLinkType()
		{
			return (linkTypes)wayne::numberUtil::bytesStaticToNumber(this->linkType, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_SHORT, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		char* interfaceDescriptionBlock::getLinkTypeExact()
		{
			char* toReturn = new char[structByteLength::IDB_LINK_TYPE_LENGTH];
			std::copy(this->linkType, this->linkType + structByteLength::IDB_LINK_TYPE_LENGTH, toReturn);
			return toReturn;
		}

		void interfaceDescriptionBlock::setLinkType(linkTypes type)
		{
			delete[] this->linkType;
			this->linkType = wayne::numberUtil::numberToBytesStatic((unsigned short)linkTypes::LINKTYPE_ETHERNET, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		void interfaceDescriptionBlock::setLinkTypeExact(const char* linkTypeExact)
		{
			delete[] this->linkType;
			this->linkType = new char[structByteLength::IDB_LINK_TYPE_LENGTH];
			std::copy(linkTypeExact, linkTypeExact + structByteLength::IDB_LINK_TYPE_LENGTH, this->linkType);
		}

		unsigned int interfaceDescriptionBlock::getSnapLength()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->snapLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		char* interfaceDescriptionBlock::getSnapLengthExact()
		{
			char* toReturn = new char[structByteLength::IDB_SNAP_LENGTH_LENGTH];
			std::copy(this->snapLength, this->snapLength + structByteLength::IDB_SNAP_LENGTH_LENGTH, toReturn);
			return toReturn;
		}

		void interfaceDescriptionBlock::setSnapLength(unsigned int newSnapLength)
		{
			delete[] this->snapLength;
			this->snapLength = wayne::numberUtil::numberToBytesStatic(newSnapLength, wayne::numberUtil::numberByteOrder::ORDER_DATA_DEFAULT);
		}

		void interfaceDescriptionBlock::setSnapLengthExact(const char* newSnapLengthExact)
		{
			delete[] this->snapLength;
			this->snapLength = new char[structByteLength::IDB_SNAP_LENGTH_LENGTH];
			std::copy(newSnapLengthExact, newSnapLengthExact + structByteLength::IDB_SNAP_LENGTH_LENGTH, this->snapLength);
		}

		optionTypes* interfaceDescriptionBlock::getAllOptionKeys()
		{
			optionTypes* allKeys = new optionTypes[this->options.size()];
			int counter = 0;
			for (auto const& [key, option] : this->options)
			{
				allKeys[counter] = key;
				counter++;
			}
			return allKeys;
		}

		unsigned int interfaceDescriptionBlock::getAllOptionsCount()
		{
			return this->options.size();
		}

		bool interfaceDescriptionBlock::isOptionAcceptable(optionTypes option)
		{
			switch (option)
			{
				case optionTypes::IF_DESCRIPTION:
				case optionTypes::IF_EUIADDR:
				case optionTypes::IF_FCSLEN:
				case optionTypes::IF_FILTER:
				case optionTypes::IF_HARDWARE:
				case optionTypes::IF_IPV4ADDR:
				case optionTypes::IF_IPV6ADDR:
				case optionTypes::IF_MACADDR:
				case optionTypes::IF_NAME:
				case optionTypes::IF_OS:
				case optionTypes::IF_RXSPEED:
				case optionTypes::IF_SPEED:
				case optionTypes::IF_TSOFFSET:
				case optionTypes::IF_TSRESOL:
				case optionTypes::IF_TXSPEED:
				case optionTypes::IF_TZONE:
					return true;
					break;
				default:
					return false;
					break;
			}
		}

		bool interfaceDescriptionBlock::isOptionExist(optionTypes option)
		{
			for (auto const& [key, value] : this->options) // @suppress("Symbol is not resolved")
			{
				if (key == option)
				{
					return true;
				}
			}
			return false;
		}

		char* interfaceDescriptionBlock::getOption(optionTypes option)
		{
			char* toReturn;
			int toReturnLength = 0;
			if (isOptionExist(option))
			{
				if (isDynamicLengthOption(option))
				{
					toReturnLength = std::strlen(this->options[option]);
				}
				else
				{
					if (isStaticLengthOptionAllowsMultiple(option))
					{
						switch (option)
						{
							case optionTypes::IF_IPV4ADDR:
								toReturnLength = (isOptionCurrentlyMultiple(option)) ? optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(option) : optionByteLength::IF_IPV4ADDR_LENGTH;
								break;
							case optionTypes::IF_IPV6ADDR:
								toReturnLength = (isOptionCurrentlyMultiple(option)) ? optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(option) : optionByteLength::IF_IPV6ADDR_LENGTH;
								break;
							default:
								break;
						}
					}
					else
					{
						switch (option)
						{
						case optionTypes::IF_MACADDR:
							toReturnLength = optionByteLength::IF_MACADDR_LENGTH;
							break;
						case optionTypes::IF_EUIADDR:
							toReturnLength = optionByteLength::IF_EUIADDR_LENGTH;
							break;
						case optionTypes::IF_SPEED:
							toReturnLength = optionByteLength::IF_SPEED_LENGTH;
							break;
						case optionTypes::IF_TSRESOL:
							toReturnLength = optionByteLength::IF_TSRESOL_LENGTH;
							break;
						case optionTypes::IF_TZONE:
							toReturnLength = optionByteLength::IF_TZONE_LENGTH;
							break;
						case optionTypes::IF_FCSLEN:
							toReturnLength = optionByteLength::IF_FCSLEN_LENGTH;
							break;
						case optionTypes::IF_TSOFFSET:
							toReturnLength = optionByteLength::IF_TSOFFSET_LENGTH;
							break;
						case optionTypes::IF_TXSPEED:
							toReturnLength = optionByteLength::IF_TXSPEED_LENGTH;
							break;
						case optionTypes::IF_RXSPEED:
							toReturnLength = optionByteLength::IF_RXSPEED_LENGTH;
							break;
						default:
							break;
							//Don't do anything.
						}
					}
				}
				toReturn = new char[toReturnLength];
				std::copy(this->options[option], this->options[option] + toReturnLength, toReturn);
				return toReturn;
			}
			else
			{
				return nullptr;
			}
		}

		bool interfaceDescriptionBlock::setOption(optionTypes option, const char* value, unsigned int valueLength)
		{
			
			if (isOptionAcceptable(option))
			{
				/* Determine the original size */
				int originalOptionLength = -1;
				if (isOptionExist(option))
				{
					if (isDynamicLengthOption(option))
					{
						originalOptionLength = std::strlen(this->options[option]);
					}
					else if (isStaticLengthOptionAllowsMultiple(option))
					{
						switch (option)
						{
							case optionTypes::IF_IPV4ADDR:
								originalOptionLength = (isOptionCurrentlyMultiple(option)) ? optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(option) : optionByteLength::IF_IPV4ADDR_LENGTH;
								if (isOptionCurrentlyMultiple(option))
								{
									this->multCounts.erase(option);
								}
								break;
							case optionTypes::IF_IPV6ADDR:
								originalOptionLength = (isOptionCurrentlyMultiple(option)) ? optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(option) : optionByteLength::IF_IPV6ADDR_LENGTH;
								if (isOptionCurrentlyMultiple(option))
								{
									this->multCounts.erase(option);
								}
								break;
							default:
								break;
						}
					}
					else
					{
						switch (option)
						{
							case optionTypes::IF_MACADDR:
								originalOptionLength = optionByteLength::IF_MACADDR_LENGTH;
								break;
							case optionTypes::IF_EUIADDR:
								originalOptionLength = optionByteLength::IF_EUIADDR_LENGTH;
								break;
							case optionTypes::IF_SPEED:
								originalOptionLength = optionByteLength::IF_SPEED_LENGTH;
								break;
							case optionTypes::IF_TSRESOL:
								originalOptionLength = optionByteLength::IF_TSRESOL_LENGTH;
								break;
							case optionTypes::IF_TZONE:
								originalOptionLength = optionByteLength::IF_TZONE_LENGTH;
								break;
							case optionTypes::IF_FCSLEN:
								originalOptionLength = optionByteLength::IF_FCSLEN_LENGTH;
								break;
							case optionTypes::IF_TSOFFSET:
								originalOptionLength = optionByteLength::IF_TSOFFSET_LENGTH;
								break;
							case optionTypes::IF_TXSPEED:
								originalOptionLength = optionByteLength::IF_TXSPEED_LENGTH;
								break;
							case optionTypes::IF_RXSPEED:
								originalOptionLength = optionByteLength::IF_RXSPEED_LENGTH;
								break;
							default:
								break;
								//Don't do anything.
						}
					}

					//Delete the data originally in the map
					delete[] this->options[option];
				}

				/* Checking validity of new size, dynamic length doesn't need to be validated. */
				if (isStaticLengthOption(option))
				{
					if (isStaticLengthOptionAllowsMultiple(option))
					{
						switch (option)
						{
							case optionTypes::IF_IPV4ADDR:
								if (valueLength % (int)optionByteLength::IF_IPV4ADDR_LENGTH == 0)
								{
									if (valueLength / (int)optionByteLength::IF_IPV4ADDR_LENGTH > 0)
									{
										this->multCounts[option] = valueLength / (int)optionByteLength::IF_IPV4ADDR_LENGTH;
									}
								}
								else
								{
									return false;
								}
								break;
							case optionTypes::IF_IPV6ADDR:
								if (valueLength % (int)optionByteLength::IF_IPV6ADDR_LENGTH == 0)
								{
									if (valueLength / (int)optionByteLength::IF_IPV6ADDR_LENGTH > 0)
									{
										this->multCounts[option] = valueLength / (int)optionByteLength::IF_IPV6ADDR_LENGTH;
									}
								}
								else
								{
									return false;
								}
								break;
							default:
								return false;
								break;
						}
					}
					switch (option)
					{
						case optionTypes::IF_MACADDR:
							if (valueLength != optionByteLength::IF_MACADDR_LENGTH)
							{
								return false;
							}
							break;
						case optionTypes::IF_EUIADDR:
							if (valueLength != optionByteLength::IF_EUIADDR_LENGTH)
							{
								return false;
							}
							break;
						case optionTypes::IF_SPEED:
							if (valueLength != optionByteLength::IF_SPEED_LENGTH)
							{
								return false;
							}
							break;
						case optionTypes::IF_TSRESOL:
							if (valueLength != optionByteLength::IF_TSRESOL_LENGTH)
							{
								return false;
							}
							break;
						case optionTypes::IF_TZONE:
							if (valueLength != optionByteLength::IF_TZONE_LENGTH)
							{
								return false;
							}
							break;
						case optionTypes::IF_FCSLEN:
							if (valueLength != optionByteLength::IF_FCSLEN_LENGTH)
							{
								return false;
							}
							break;
						case optionTypes::IF_TSOFFSET:
							if (valueLength != optionByteLength::IF_TSOFFSET_LENGTH)
							{
								return false;
							}
							break;
						case optionTypes::IF_TXSPEED:
							if (valueLength != optionByteLength::IF_TXSPEED_LENGTH)
							{
								return false;
							}
							break;
						case optionTypes::IF_RXSPEED:
							if (valueLength != optionByteLength::IF_RXSPEED_LENGTH)
							{
								return false;
							}
							break;
						default:
							break;
							//Don't do anything.
					}

				}

				//If there is original data
				if (originalOptionLength > 0)
				{
					updateBlockLength(-((int)4 + originalOptionLength)); // Decrease the size based on origianl data.
				}
				// Appending new size.
				updateBlockLength(wayne::numberUtil::nextNearestMultOfXFromY((int)4 + (int)valueLength, (int)structByteLength::BLOCK_READ_UNIT)); //Add tghe size of the new data.
				/* End of handling size */

				/* Copy data*/
				this->options[option] = new char[valueLength];
				std::copy(value, value + valueLength, this->options[option]);
				return true;
			}
			else
			{
				return false;
			}
		}

		bool interfaceDescriptionBlock::isOptionCurrentlyMultiple(optionTypes option)
		{
			if (this->multCounts.empty()) // @suppress("Field cannot be resolved") // @suppress("Method cannot be resolved")
			{
				return false;
			}
			else
			{
				optionTypes* allKeys = new optionTypes[multCounts.size()]; // @suppress("Field cannot be resolved") // @suppress("Method cannot be resolved")
				for (auto const& [key, value] : this->multCounts) // @suppress("Symbol is not resolved") // @suppress("Field cannot be resolved")
				{
					if (key == option)
					{
						return true;
					}
				}
				return false;
			}
		}

		unsigned int interfaceDescriptionBlock::getCurrentMultipleOptionsMult(optionTypes option)
		{
			if (isOptionCurrentlyMultiple(option))
			{
				return (unsigned int)0;
			}
			else
			{
				return this->multCounts[option]; // @suppress("Field cannot be resolved")
			}
		}

		bool interfaceDescriptionBlock::isDynamicLengthOption(optionTypes option)
		{
			switch (option)
			{
				case optionTypes::IF_NAME:
				case optionTypes::IF_DESCRIPTION:
				case optionTypes::IF_FILTER:
				case optionTypes::IF_OS:
				case optionTypes::IF_HARDWARE:
					return true;
				default:
					return false;
					break;
			}
		}

		bool interfaceDescriptionBlock::isStaticLengthOption(optionTypes option)
		{
			switch (option)
			{
				case optionTypes::IF_IPV4ADDR:
				case optionTypes::IF_IPV6ADDR:
				case optionTypes::IF_MACADDR:
				case optionTypes::IF_EUIADDR:
				case optionTypes::IF_SPEED:
				case optionTypes::IF_TSRESOL:
				case optionTypes::IF_TZONE:
				case optionTypes::IF_FCSLEN:
				case optionTypes::IF_TSOFFSET:
				case optionTypes::IF_TXSPEED:
				case optionTypes::IF_RXSPEED:
					return true;
					break;
				default:
					return false;
					break;
			}
		}

		bool interfaceDescriptionBlock::isStaticLengthOptionAllowsMultiple(optionTypes option)
		{
			if (this->options.empty())
			{
				return false;
			}
			else
			{
				switch (option)
				{
					case optionTypes::IF_IPV4ADDR:
					case optionTypes::IF_IPV6ADDR:
						return true;
						break;
					default:
						return false;
				}
			}
		}


	} /* namespace PCAP */
} /* namespace wayne */
