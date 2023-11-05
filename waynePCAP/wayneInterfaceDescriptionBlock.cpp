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

		interfaceDescriptionBlock::interfaceDescriptionBlock() {
			setBlockType(blockTypes::INTERFACE_DESCRIPTION);
			setLinkType(linkTypes::LINKTYPE_ETHERNET);
			this->reserved = wayne::numberUtil::numberToBytesStatic(short(0));
			setSnapLength((unsigned int)262144);

			updateBlockLength(structByteLength::IDB_LINK_TYPE_LENGTH + structByteLength::IDB_RESERVED_LENGTH);
			updateBlockLength(structByteLength::IDB_SNAP_LENGTH);
		}

		interfaceDescriptionBlock::interfaceDescriptionBlock(linkTypes initType, unsigned int initSnapLength) {
			setBlockType(blockTypes::INTERFACE_DESCRIPTION);
			setLinkType(initType);
			this->reserved = wayne::numberUtil::numberToBytesStatic(short(0));
			setSnapLength(initSnapLength);
			updateBlockLength(structByteLength::IDB_LINK_TYPE_LENGTH + structByteLength::IDB_RESERVED_LENGTH);
			updateBlockLength(structByteLength::IDB_SNAP_LENGTH);
		}

		interfaceDescriptionBlock::~interfaceDescriptionBlock() {
			delete[] this->linkType;
			delete[] this->reserved;
			delete[] this->snapLength;
			for (auto const& [key, option] : this->options) // @suppress("Symbol is not resolved")
			{
				delete[] option;

			}
			options.clear(); // @suppress("Method cannot be resolved")
		}

		interfaceDescriptionBlock::interfaceDescriptionBlock(const interfaceDescriptionBlock &other) {
			setLinkTypeExact(other.linkType);
			delete this->reserved;
			this->reserved = wayne::numberUtil::numberToBytesStatic(short(0));
			setSnapLengthExact(other.snapLength);

			this->multCounts.clear(); // @suppress("Method cannot be resolved")
			for (auto const& [key, option] : other.multCounts) // @suppress("Symbol is not resolved")
			{
				this->multCounts.insert(std::pair<optionTypes, unsigned int>(key, option)); // @suppress("Method cannot be resolved") // @suppress("Symbol is not resolved")
			}

			this->options.clear(); // @suppress("Method cannot be resolved")
			for (auto const& [key, option] : other.options) // @suppress("Symbol is not resolved")
			{
				if (isDynamicLengthOption(key)) // @suppress("Invalid arguments")
				{
					char* newOption = new char[std::strlen(option)]; // @suppress("Invalid arguments")
					std::copy(option, option + std::strlen(option), newOption); // @suppress("Invalid arguments")
					this->options.insert(std::pair<optionTypes, char*>(key, option)); // @suppress("Symbol is not resolved") // @suppress("Method cannot be resolved")
				}
				else
				{
					char* newOption;
					if (isStaticLengthOptionAllowsMultiple(key)) // @suppress("Invalid arguments")
					{
						if (isOptionCurrentlyMultiple(key)) // @suppress("Invalid arguments")
						{
							switch (key)
							{
							case optionTypes::IF_IPV4ADDR:
								newOption = new char[optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key)]; // @suppress("Invalid arguments")
								std::copy(option, option + (optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key)), newOption); // @suppress("Invalid arguments")
								break;
							case optionTypes::IF_IPV6ADDR:
								newOption = new char[optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key)]; // @suppress("Invalid arguments")
								std::copy(option, option + (optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key)), newOption); // @suppress("Invalid arguments")
								break;
							default:
								// Do nothing
								break;
							}
						}
						else
						{
							switch (key)
							{
							case optionTypes::IF_IPV4ADDR:
								newOption = new char[optionByteLength::IF_IPV4ADDR_LENGTH];
								std::copy(option, option + optionByteLength::IF_IPV4ADDR_LENGTH, newOption); // @suppress("Invalid arguments")
								break;
							case optionTypes::IF_IPV6ADDR:
								newOption = new char[optionByteLength::IF_IPV6ADDR_LENGTH];
								std::copy(option, option + optionByteLength::IF_IPV6ADDR_LENGTH, newOption); // @suppress("Invalid arguments")
								break;
							default:
								// Do nothing
								break;
							}
						}
					}
					else
					{
						char* newOption;
						switch (key)
						{
						case optionTypes::IF_MACADDR:
							newOption = new char[optionByteLength::IF_MACADDR_LENGTH];
							std::copy(option, option + optionByteLength::IF_MACADDR_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_EUIADDR:
							newOption = new char[optionByteLength::IF_EUIADDR_LENGTH];
							std::copy(option, option + optionByteLength::IF_EUIADDR_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_SPEED:
							newOption = new char[optionByteLength::IF_SPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_SPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TSRESOL:
							newOption = new char[optionByteLength::IF_TSRESOL_LENGTH];
							std::copy(option, option + optionByteLength::IF_TSRESOL_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TZONE:
							newOption = new char[optionByteLength::IF_TZONE_LENGTH];
							std::copy(option, option + optionByteLength::IF_TZONE_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_FCSLEN:
							newOption = new char[optionByteLength::IF_FCSLEN_LENGTH];
							std::copy(option, option + optionByteLength::IF_FCSLEN_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TSOFFSET:
							newOption = new char[optionByteLength::IF_TSOFFSET_LENGTH];
							std::copy(option, option + optionByteLength::IF_TSOFFSET_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TXSPEED:
							newOption = new char[optionByteLength::IF_TXSPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_TXSPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_RXSPEED:
							newOption = new char[optionByteLength::IF_RXSPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_RXSPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						default:
							//Don't do anything.
						}
					}
				}
			}
		}

		interfaceDescriptionBlock::interfaceDescriptionBlock(interfaceDescriptionBlock &&other) {
			setLinkTypeExact(other.linkType);
			delete[] other.linkType;

			delete this->reserved;
			this->reserved = wayne::numberUtil::numberToBytesStatic(short(0));
			delete[] other.reserved;

			setSnapLengthExact(other.snapLength);
			delete[] other.snapLength;

			this->multCounts.clear(); // @suppress("Method cannot be resolved")
			for (auto const& [key, option] : other.multCounts) // @suppress("Symbol is not resolved")
			{
				this->multCounts.insert(std::pair<optionTypes, unsigned int>(key, option)); // @suppress("Method cannot be resolved") // @suppress("Symbol is not resolved")
			}
			other.multCounts.clear(); // @suppress("Method cannot be resolved")

			this->options.clear(); // @suppress("Method cannot be resolved")
			for (auto const& [key, option] : other.options) // @suppress("Symbol is not resolved")
			{
				if (isDynamicLengthOption(key)) // @suppress("Invalid arguments")
				{
					char* newOption = new char[std::strlen(option)]; // @suppress("Invalid arguments")
					std::copy(option, option + std::strlen(option), newOption); // @suppress("Invalid arguments")
					this->options.insert(std::pair<optionTypes, char*>(key, option)); // @suppress("Symbol is not resolved") // @suppress("Method cannot be resolved")
				}
				else
				{
					char* newOption;
					if (isStaticLengthOptionAllowsMultiple(key)) // @suppress("Invalid arguments")
					{
						if (isOptionCurrentlyMultiple(key)) // @suppress("Invalid arguments")
						{
							switch (key)
							{
							case optionTypes::IF_IPV4ADDR:
								newOption = new char[optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key)]; // @suppress("Invalid arguments")
								std::copy(option, option + (optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key)), newOption); // @suppress("Invalid arguments")
								break;
							case optionTypes::IF_IPV6ADDR:
								newOption = new char[optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key)]; // @suppress("Invalid arguments")
								std::copy(option, option + (optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key)), newOption); // @suppress("Invalid arguments")
								break;
							default:
								// Do nothing
								break;
							}
						}
						else
						{
							switch (key)
							{
							case optionTypes::IF_IPV4ADDR:
								newOption = new char[optionByteLength::IF_IPV4ADDR_LENGTH];
								std::copy(option, option + optionByteLength::IF_IPV4ADDR_LENGTH, newOption); // @suppress("Invalid arguments")
								break;
							case optionTypes::IF_IPV6ADDR:
								newOption = new char[optionByteLength::IF_IPV6ADDR_LENGTH];
								std::copy(option, option + optionByteLength::IF_IPV6ADDR_LENGTH, newOption); // @suppress("Invalid arguments")
								break;
							default:
								// Do nothing
								break;
							}
						}
					}
					else
					{
						char* newOption;
						switch (key)
						{
						case optionTypes::IF_MACADDR:
							newOption = new char[optionByteLength::IF_MACADDR_LENGTH];
							std::copy(option, option + optionByteLength::IF_MACADDR_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_EUIADDR:
							newOption = new char[optionByteLength::IF_EUIADDR_LENGTH];
							std::copy(option, option + optionByteLength::IF_EUIADDR_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_SPEED:
							newOption = new char[optionByteLength::IF_SPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_SPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TSRESOL:
							newOption = new char[optionByteLength::IF_TSRESOL_LENGTH];
							std::copy(option, option + optionByteLength::IF_TSRESOL_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TZONE:
							newOption = new char[optionByteLength::IF_TZONE_LENGTH];
							std::copy(option, option + optionByteLength::IF_TZONE_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_FCSLEN:
							newOption = new char[optionByteLength::IF_FCSLEN_LENGTH];
							std::copy(option, option + optionByteLength::IF_FCSLEN_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TSOFFSET:
							newOption = new char[optionByteLength::IF_TSOFFSET_LENGTH];
							std::copy(option, option + optionByteLength::IF_TSOFFSET_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TXSPEED:
							newOption = new char[optionByteLength::IF_TXSPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_TXSPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_RXSPEED:
							newOption = new char[optionByteLength::IF_RXSPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_RXSPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						default:
							//Don't do anything.
						}
					}
				}
				delete[] option;
			}
			other.options.clear(); // @suppress("Method cannot be resolved")
		}

		interfaceDescriptionBlock& interfaceDescriptionBlock::operator=(const interfaceDescriptionBlock &other) {
			setLinkTypeExact(other.linkType);
			delete this->reserved;
			this->reserved = wayne::numberUtil::numberToBytesStatic(short(0));
			setSnapLengthExact(other.snapLength);

			this->multCounts.clear(); // @suppress("Method cannot be resolved")
			for (auto const& [key, option] : other.multCounts) // @suppress("Symbol is not resolved")
			{
				this->multCounts.insert(std::pair<optionTypes, unsigned int>(key, option)); // @suppress("Method cannot be resolved") // @suppress("Symbol is not resolved")
			}

			this->options.clear(); // @suppress("Method cannot be resolved")
			for (auto const& [key, option] : other.options) // @suppress("Symbol is not resolved")
			{
				if (isDynamicLengthOption(key)) // @suppress("Invalid arguments")
				{
					char* newOption = new char[std::strlen(option)]; // @suppress("Invalid arguments")
					std::copy(option, option + std::strlen(option), newOption); // @suppress("Invalid arguments")
					this->options.insert(std::pair<optionTypes, char*>(key, option)); // @suppress("Symbol is not resolved") // @suppress("Method cannot be resolved")
				}
				else
				{
					char* newOption;
					if (isStaticLengthOptionAllowsMultiple(key)) // @suppress("Invalid arguments")
					{
						if (isOptionCurrentlyMultiple(key)) // @suppress("Invalid arguments")
						{
							switch (key)
							{
							case optionTypes::IF_IPV4ADDR:
								newOption = new char[optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key)]; // @suppress("Invalid arguments")
								std::copy(option, option + (optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key)), newOption); // @suppress("Invalid arguments")
								break;
							case optionTypes::IF_IPV6ADDR:
								newOption = new char[optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key)]; // @suppress("Invalid arguments")
								std::copy(option, option + (optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key)), newOption); // @suppress("Invalid arguments")
								break;
							default:
								// Do nothing
								break;
							}
						}
						else
						{
							switch (key)
							{
							case optionTypes::IF_IPV4ADDR:
								newOption = new char[optionByteLength::IF_IPV4ADDR_LENGTH];
								std::copy(option, option + optionByteLength::IF_IPV4ADDR_LENGTH, newOption); // @suppress("Invalid arguments")
								break;
							case optionTypes::IF_IPV6ADDR:
								newOption = new char[optionByteLength::IF_IPV6ADDR_LENGTH];
								std::copy(option, option + optionByteLength::IF_IPV6ADDR_LENGTH, newOption); // @suppress("Invalid arguments")
								break;
							default:
								// Do nothing
								break;
							}
						}
					}
					else
					{
						char* newOption;
						switch (key)
						{
						case optionTypes::IF_MACADDR:
							newOption = new char[optionByteLength::IF_MACADDR_LENGTH];
							std::copy(option, option + optionByteLength::IF_MACADDR_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_EUIADDR:
							newOption = new char[optionByteLength::IF_EUIADDR_LENGTH];
							std::copy(option, option + optionByteLength::IF_EUIADDR_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_SPEED:
							newOption = new char[optionByteLength::IF_SPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_SPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TSRESOL:
							newOption = new char[optionByteLength::IF_TSRESOL_LENGTH];
							std::copy(option, option + optionByteLength::IF_TSRESOL_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TZONE:
							newOption = new char[optionByteLength::IF_TZONE_LENGTH];
							std::copy(option, option + optionByteLength::IF_TZONE_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_FCSLEN:
							newOption = new char[optionByteLength::IF_FCSLEN_LENGTH];
							std::copy(option, option + optionByteLength::IF_FCSLEN_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TSOFFSET:
							newOption = new char[optionByteLength::IF_TSOFFSET_LENGTH];
							std::copy(option, option + optionByteLength::IF_TSOFFSET_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TXSPEED:
							newOption = new char[optionByteLength::IF_TXSPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_TXSPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_RXSPEED:
							newOption = new char[optionByteLength::IF_RXSPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_RXSPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						default:
							//Don't do anything.
						}
					}
				}
			}
			return *this;
		}

		interfaceDescriptionBlock& interfaceDescriptionBlock::operator=(interfaceDescriptionBlock &&other) {
			setLinkTypeExact(other.linkType);
			delete[] other.linkType;

			delete this->reserved;
			this->reserved = wayne::numberUtil::numberToBytesStatic(short(0));
			delete[] other.reserved;

			setSnapLengthExact(other.snapLength);
			delete[] other.snapLength;

			this->multCounts.clear(); // @suppress("Method cannot be resolved")
			for (auto const& [key, option] : other.multCounts) // @suppress("Symbol is not resolved")
			{
				this->multCounts.insert(std::pair<optionTypes, unsigned int>(key, option)); // @suppress("Method cannot be resolved") // @suppress("Symbol is not resolved")
			}
			other.multCounts.clear(); // @suppress("Method cannot be resolved")

			this->options.clear(); // @suppress("Method cannot be resolved")
			for (auto const& [key, option] : other.options) // @suppress("Symbol is not resolved")
			{
				if (isDynamicLengthOption(key)) // @suppress("Invalid arguments")
				{
					char* newOption = new char[std::strlen(option)]; // @suppress("Invalid arguments")
					std::copy(option, option + std::strlen(option), newOption); // @suppress("Invalid arguments")
					this->options.insert(std::pair<optionTypes, char*>(key, option)); // @suppress("Symbol is not resolved") // @suppress("Method cannot be resolved")
				}
				else
				{
					char* newOption;
					if (isStaticLengthOptionAllowsMultiple(key)) // @suppress("Invalid arguments")
					{
						if (isOptionCurrentlyMultiple(key)) // @suppress("Invalid arguments")
						{
							switch (key)
							{
							case optionTypes::IF_IPV4ADDR:
								newOption = new char[optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key)]; // @suppress("Invalid arguments")
								std::copy(option, option + (optionByteLength::IF_IPV4ADDR_LENGTH * getCurrentMultipleOptionsMult(key)), newOption); // @suppress("Invalid arguments")
								break;
							case optionTypes::IF_IPV6ADDR:
								newOption = new char[optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key)]; // @suppress("Invalid arguments")
								std::copy(option, option + (optionByteLength::IF_IPV6ADDR_LENGTH * getCurrentMultipleOptionsMult(key)), newOption); // @suppress("Invalid arguments")
								break;
							default:
								// Do nothing
								break;
							}
						}
						else
						{
							switch (key)
							{
							case optionTypes::IF_IPV4ADDR:
								newOption = new char[optionByteLength::IF_IPV4ADDR_LENGTH];
								std::copy(option, option + optionByteLength::IF_IPV4ADDR_LENGTH, newOption); // @suppress("Invalid arguments")
								break;
							case optionTypes::IF_IPV6ADDR:
								newOption = new char[optionByteLength::IF_IPV6ADDR_LENGTH];
								std::copy(option, option + optionByteLength::IF_IPV6ADDR_LENGTH, newOption); // @suppress("Invalid arguments")
								break;
							default:
								// Do nothing
								break;
							}
						}
					}
					else
					{
						char* newOption;
						switch (key)
						{
						case optionTypes::IF_MACADDR:
							newOption = new char[optionByteLength::IF_MACADDR_LENGTH];
							std::copy(option, option + optionByteLength::IF_MACADDR_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_EUIADDR:
							newOption = new char[optionByteLength::IF_EUIADDR_LENGTH];
							std::copy(option, option + optionByteLength::IF_EUIADDR_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_SPEED:
							newOption = new char[optionByteLength::IF_SPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_SPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TSRESOL:
							newOption = new char[optionByteLength::IF_TSRESOL_LENGTH];
							std::copy(option, option + optionByteLength::IF_TSRESOL_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TZONE:
							newOption = new char[optionByteLength::IF_TZONE_LENGTH];
							std::copy(option, option + optionByteLength::IF_TZONE_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_FCSLEN:
							newOption = new char[optionByteLength::IF_FCSLEN_LENGTH];
							std::copy(option, option + optionByteLength::IF_FCSLEN_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TSOFFSET:
							newOption = new char[optionByteLength::IF_TSOFFSET_LENGTH];
							std::copy(option, option + optionByteLength::IF_TSOFFSET_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_TXSPEED:
							newOption = new char[optionByteLength::IF_TXSPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_TXSPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						case optionTypes::IF_RXSPEED:
							newOption = new char[optionByteLength::IF_RXSPEED_LENGTH];
							std::copy(option, option + optionByteLength::IF_RXSPEED_LENGTH, newOption); // @suppress("Invalid arguments")
							break;
						default:
							//Don't do anything.
						}
					}
				}
				delete[] option;
			}
			other.options.clear(); // @suppress("Method cannot be resolved")
			return *this;
		}

		linkTypes interfaceDescriptionBlock::getLinkType()
		{
			return (linkTypes)wayne::numberUtil::bytesStaticToNumber(this->linkType, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_SHORT);
		}

		char* interfaceDescriptionBlock::getLinkTypeExact()
		{
			return this->linkType;
		}

		void interfaceDescriptionBlock::setLinkType(linkTypes type)
		{
			delete[] this->linkType;
			this->linkType = wayne::numberUtil::numberToBytesStatic((unsigned short)linkTypes::LINKTYPE_ETHERNET);
		}

		void interfaceDescriptionBlock::setLinkTypeExact(const char* linkTypeExact)
		{
			delete[] this->linkType;
			this->linkType = new char[structByteLength::IDB_LINK_TYPE_LENGTH];
			std::copy(linkTypeExact, linkTypeExact + structByteLength::IDB_LINK_TYPE_LENGTH, this->linkType);
		}

		unsigned int interfaceDescriptionBlock::getSnapLength()
		{
			return wayne::numberUtil::bytesStaticToNumber(this->snapLength, wayne::numberUtil::numberTypeReference::DATA_TYPE_UNSIGNED_INTEGER);
		}

		char* interfaceDescriptionBlock::getSnapLengthExact()
		{
			return this->snapLength;
		}

		void interfaceDescriptionBlock::setSnapLength(unsigned int newSnapLength)
		{
			delete[] this->snapLength;
			this->snapLength = wayne::numberUtil::numberToBytesStatic(newSnapLength);
		}

		void interfaceDescriptionBlock::setSnapLengthExact(const char* newSnapLengthExact)
		{
			delete[] this->snapLength;
			this->snapLength = new char[structByteLength::IDB_SNAP_LENGTH];
			std::copy(newSnapLengthExact, newSnapLengthExact + structByteLength::IDB_SNAP_LENGTH, this->snapLength);
		}

		optionTypes* interfaceDescriptionBlock::getAllOptionKeys()
		{
			optionTypes* allKeys = new optionTypes[this->options.size()]; // @suppress("Method cannot be resolved")
			int counter = 0;
			for (auto const& [key, option] : this->options) // @suppress("Symbol is not resolved")
			{
				allKeys[counter] = key;
				counter++;
			}
			return allKeys;
		}

		unsigned int interfaceDescriptionBlock::getAllOptionsCount()
		{
			return this->options.size(); // @suppress("Method cannot be resolved")
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
			if (isDynamicLengthOption(option))
			{
				toReturn = new char[std::strlen(this->options[option])];
				std::copy(this->options[option], this->options[option] + std::strlen(this->options[option]), toReturn);
				return toReturn;
			}
			else
			{
				if (isOptionCurrentlyMultiple(option))
				{
					switch (option)
					{
						case optionTypes::IF_IPV4ADDR:
						toReturn = new char[optionByteLength::IF_IPV4ADDR_LENGTH * this->multCounts[option]];
						std::copy(this->options[option], this->options[option] + (optionByteLength::IF_IPV4ADDR_LENGTH * this->multCounts[option]), toReturn);
						return toReturn;
						break;
						case optionTypes::IF_IPV6ADDR:
						toReturn = new char[optionByteLength::IF_IPV6ADDR_LENGTH * this->multCounts[option]];
						std::copy(this->options[option], this->options[option] + (optionByteLength::IF_IPV6ADDR_LENGTH * this->multCounts[option]), toReturn);
						return toReturn;
						break;
						default:
						return toReturn;
						break;
					}
				}
				else
				{
					switch (option)
					{
						case optionTypes::IF_IPV4ADDR:
							toReturn = new char[optionByteLength::IF_IPV4ADDR_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_IPV4ADDR_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_IPV6ADDR:
							toReturn = new char[optionByteLength::IF_IPV6ADDR_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_IPV6ADDR_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_MACADDR:
							toReturn = new char[optionByteLength::IF_MACADDR_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_MACADDR_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_EUIADDR:
							toReturn = new char[optionByteLength::IF_EUIADDR_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_EUIADDR_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_SPEED:
							toReturn = new char[optionByteLength::IF_SPEED_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_SPEED_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_TSRESOL:
							toReturn = new char[optionByteLength::IF_TSRESOL_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_TSRESOL_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_TZONE:
							toReturn = new char[optionByteLength::IF_TZONE_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_TZONE_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_FCSLEN:
							toReturn = new char[optionByteLength::IF_FCSLEN_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_FCSLEN_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_TSOFFSET:
							toReturn = new char[optionByteLength::IF_TSOFFSET_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_TSOFFSET_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_TXSPEED:
							toReturn = new char[optionByteLength::IF_TXSPEED_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_TXSPEED_LENGTH, toReturn);
							return toReturn;
							break;
						case optionTypes::IF_RXSPEED:
							toReturn = new char[optionByteLength::IF_RXSPEED_LENGTH];
							std::copy(this->options[option], this->options[option] + optionByteLength::IF_RXSPEED_LENGTH, toReturn);
							return toReturn;
							break;
						default:
							return toReturn;
							break;
					}
				}
			}
		}

		bool interfaceDescriptionBlock::setOption(optionTypes option, const char* value, unsigned int valueLength)
		{
			if (isOptionAcceptable(option))
			{
				/* Handling the length request. */	
				if (isOptionExist(option))
				{
					int originalOptionLength = 0;
					if (isDynamicLengthOption(option))
					{
						int recoveredLength = std::strlen(this->options[option]);
						updateBlockLength(-recoveredLength);
						updateBlockLength(valueLength);
					}
					else
					{
						if (isStaticLengthOptionAllowsMultiple(option))
						{
							switch (option)
							{
								case optionTypes::IF_IPV4ADDR:
								if (valueLength % (int)optionByteLength::IF_IPV4ADDR_LENGTH != 0)
								{
									return false;
								}
								if (isOptionCurrentlyMultiple(option))
								{
									int recoveredLength = (int)optionByteLength::IF_IPV4ADDR_LENGTH * (int)this->multCounts[option];
									this->multCounts.erase(option);
									updateBlockLength(-recoveredLength);
								}
								else
								{
									updateBlockLength(-((int)optionByteLength::IF_IPV4ADDR_LENGTH));
								}
								int multIpv4 = valueLength / (int)optionByteLength::IF_IPV4ADDR_LENGTH;
								if (multIpv4 > 1)
								{
									this->multCounts[option] = multIpv4;
								}
								updateBlockLength(valueLength);
								break;
								case optionTypes::IF_IPV6ADDR:
								if (valueLength % (int)optionByteLength::IF_IPV6ADDR_LENGTH != 0)
								{
									return false;
								}
								if (isOptionCurrentlyMultiple(option))
								{
									int recoveredLength = wayne::numberUtil::nextNearestMultOfXFromY((int)optionByteLength::IF_IPV6ADDR_LENGTH * (int)this->multCounts[option], (int)structByteLength::BLOCK_READ_UNIT);
									this->multCounts.erase(option);
									updateBlockLength(-recoveredLength);
								}
								else
								{
									updateBlockLength(-(wayne::numberUtil::nextNearestMultOfXFromY((int)optionByteLength::IF_IPV4ADDR_LENGTH, (int)structByteLength::BLOCK_READ_UNIT)));
								}
								int multIpv6 = valueLength / (int)optionByteLength::IF_IPV6ADDR_LENGTH;
								if (multIpv6 > 1)
								{
									this->multCounts[option] = multIpv6;
								}
								updateBlockLength(wayne::numberUtil::nextNearestMultOfXFromY((int)valueLength, (int)structByteLength::BLOCK_READ_UNIT));
								break;
								default:
								return false;
								break;
							}
						}
					}
				}
				else
				{
					if (isDynamicLengthOption(option))
					{
						updateBlockLength((int)4 + wayne::numberUtil::nextNearestMultOfXFromY((int)valueLength, (int)structByteLength::BLOCK_READ_UNIT));
					}
					else
					{
						if(isStaticLengthOptionAllowsMultiple(option))
						{
							switch (option)
							{
								case optionTypes::IF_IPV4ADDR:
								if (valueLength % (int)optionByteLength::IF_IPV4ADDR_LENGTH == 0)
								{
									int multIpv4 = valueLength / (int)optionByteLength::IF_IPV4ADDR_LENGTH;
									if (multIpv4 > 1)
									{
										this->multCounts[optionTypes::IF_IPV4ADDR] = multIpv4;
									}
									updateBlockLength((int)4 + valueLength);
								}
								else
								{
									return false;
								}
								break;
								case optionTypes::IF_IPV6ADDR:
								if (valueLength % (int)optionByteLength::IF_IPV6ADDR_LENGTH == 0)
								{
									int multIpv6 = valueLength / (int)optionByteLength::IF_IPV6ADDR_LENGTH;
									if (multIpv6 > 1)
									{
										this->multCounts[optionTypes::IF_IPV6ADDR] = multIpv6;
									}
									updateBlockLength((int)4 + wayne::numberUtil::nextNearestMultOfXFromY((int)valueLength, (int)structByteLength::BLOCK_READ_UNIT));
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
						else
						{
							switch (option)
							{
							case optionTypes::IF_MACADDR:
								if (valueLength != optionByteLength::IF_MACADDR_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + wayne::numberUtil::nextNearestMultOfXFromY((int)optionByteLength::IF_MACADDR_LENGTH, (int)structByteLength::BLOCK_READ_UNIT));
								// Note: Because MAC Address is only 6 bytes, so it needs to be padded.
								break;
							case optionTypes::IF_EUIADDR:
								if (valueLength != optionByteLength::IF_EUIADDR_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::IF_EUIADDR_LENGTH);
								break;
							case optionTypes::IF_SPEED:
								if (valueLength != optionByteLength::IF_SPEED_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::IF_SPEED_LENGTH);
								break;
							case optionTypes::IF_TSRESOL:
								if (valueLength != optionByteLength::IF_TSRESOL_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + wayne::numberUtil::nextNearestMultOfXFromY((int)optionByteLength::IF_TSRESOL_LENGTH, (int)structByteLength::BLOCK_READ_UNIT));
								// Note: Because TSRESOL is only 1 byte, so it needs to be padded.
								break;
							case optionTypes::IF_TZONE:
								if (valueLength != optionByteLength::IF_TZONE_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::IF_TZONE_LENGTH);
								break;
							case optionTypes::IF_FCSLEN:
								if (valueLength != optionByteLength::IF_FCSLEN_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + wayne::numberUtil::nextNearestMultOfXFromY((int)optionByteLength::IF_FCSLEN_LENGTH, (int)structByteLength::BLOCK_READ_UNIT));
								break;
							case optionTypes::IF_TSOFFSET:
								if (valueLength != optionByteLength::IF_TSOFFSET_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::IF_TSOFFSET_LENGTH);
								break;
							case optionTypes::IF_TXSPEED:
								if (valueLength != optionByteLength::IF_TXSPEED_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::IF_TXSPEED_LENGTH);
								break;
							case optionTypes::IF_RXSPEED:
								if (valueLength != optionByteLength::IF_RXSPEED_LENGTH)
								{
									return false;
								}
								updateBlockLength((int)4 + optionByteLength::IF_RXSPEED_LENGTH);
								break;
							default:
								return false;
								break;
							}
						}
					}
				}
				/* End of Handling Length */
				/* 4 Nov, here. Wayne. Handling data copying.*/
				
				/* Check if this option exist*/
				if (isOptionExist(option))
				{
					delete[] this->options[option];
				}
				char* newOption = new char[valueLength];
				std::copy(value, value + valueLength, newOption);
				this->options[option] = newOption;
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


	} /* namespace PCAP */
} /* namespace wayne */
