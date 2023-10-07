/*
 * waynePCAP.hpp
 *
 *  Created on: 2023年10月7日
 *      Author: weich
 */

#ifndef LIB_WAYNEPCAP_HPP_
#define LIB_WAYNEPCAP_HPP_
#include <map>
#include <string>

namespace wayne {

struct PCAPHeaderBlock{
private:
	const char* blockType = 0x0A0D0D0A;
	int totalLength;	/*Calculated*/
	char* byteOrder;
	int majorVersion = 1;
	int minorVersion = 0;
	char* sectionLength = 0xFF; /*Value must always aligned to 32 bit.*/ /*Calculated*/
	std::map<std::string, std::string> options; // @suppress("Invalid template argument")

public:
	/* Constructor */
	PCAPHeaderBlock();
	virtual ~PCAPHeaderBlock();
	PCAPHeaderBlock(const PCAPHeaderBlock &other);
	PCAPHeaderBlock(PCAPHeaderBlock &&other);
	PCAPHeaderBlock operator=(const PCAPHeaderBlock &other);
	PCAPHeaderBlock operator=(PCAPHeaderBlock &&other);

	int getTotalLength(); /*Should not be changeable*/
	char* getByteOrder();
	int getMajorVersion();
	int getMinorVersion();
	char* getSectionLength(); /*Should not be changeable*/
	std::map<std::string> getAllOptions();
	std::string* getAllOptions();
	char** getAllOptions();

	bool setByteOrder(char* newByteOrder);
	bool setMajorVersion(int newMajorVersion);
	bool setMinorVersion(int newMinorVersion);



};


class PCAP {
public:
	PCAP();
	virtual ~PCAP();
	PCAP(const PCAP &other);
	PCAP(PCAP &&other);
	PCAP& operator=(const PCAP &other);
	PCAP& operator=(PCAP &&other);
private:

};

} /* namespace wayne */

#endif /* LIB_WAYNEPCAP_HPP_ */
