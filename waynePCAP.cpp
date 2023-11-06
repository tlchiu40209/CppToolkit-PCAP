/*
 * waynePCAP.cpp
 *
 *  Created on: 2023年10月7日
 *      Author: weich
 */

#include "waynePCAP.hpp"

namespace wayne
{
	namespace PCAP
	{
		PCAPNG::PCAPNG()
		{

		}

		PCAPNG::PCAPNG(const PCAPNG &other)
		{

		}

		PCAPNG::PCAPNG(PCAPNG &&other)
		{

		}
		
		PCAPNG::~PCAPNG()
		{
			
		}

		PCAPNG& PCAPNG::operator=(const PCAPNG &other)
		{

		}

		PCAPNG& PCAPNG::operator=(PCAPNG &&other)
		{

		}

		bool PCAPNG::operator==(const PCAPNG &other)
		{

		}

		sectionHeaderBlock PCAPNG::getSectionHeader()
		{
			return this->sectionHeader;
		}

		void PCAPNG::setSectionHeader(sectionHeaderBlock newSectionHeader)
		{
			this->sectionHeader = newSectionHeader;
		}

		interfaceDescriptionBlock PCAPNG::getInterfaceDescriptionBlock()
		{
			return this->interfaceDescription;
		}

		void PCAPNG::setInterfaceDescriptionBlock(interfaceDescriptionBlock newInterfaceDescription)
		{
			this->interfaceDescription = newInterfaceDescription;
		}

	}
} /* namespace wayne */
