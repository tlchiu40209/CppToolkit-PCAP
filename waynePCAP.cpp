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
        enum blockTypes
        {
            sectionHeaderBlock,
            interfaceDescriptionBlock,
            enhancedPacketBlock,
            simplePacketBlock,
            nameResolutionBlock,
            interfaceStatisticsBlock,
            systemdJournalExportBlock,
            decryptionSecrestsBlock,
            customBlock
        };

        class byteSeqs
        {
        public:
            static char* BYTE_ORDER_BIG_ENDIAN = "\x1a\x2b\x3c\x4d";
            static char* BYTE_ORDER_SMALL_ENDIAN = "\x4d\x3c\x2b\x1a";
        };

        class identBytes
        {
        public:
            static char* OPT_ENDOFOPT  = "\x00\x00";
            static char* OPT_COMMENT = "\x01\x00";
            static char* SHB_HARDWARE = "\x02\x00";
            static char* SHB_OS = "\x03\x00";
            static char* SHB_USERAPPL = "\x04\x00";
            static char* IDB_IF_NAME = "\x02\x00";
            static char* IDB_IF_DESCRIPTION = "\x03\x00";
            static char* IDB_IF_IPV4ADDR = "\x04\x00";
            static char* IDB_IF_IPV6ADDR = "\x05\x00";
            static char* IDB_IF_MACADDR = "\x06\00";
            static char* IDB_IF_EUIADDR = "\x07\x00";
            static char* IDB_IF_SPEED = "\x08\x00";
            static char* IDB_IF_TSRESOL = "\x09\x00";
            static char* IDB_IF_TZONE = "\x0a\x00";
            static char* IDB_IF_FILTER = "\x0b\x00";
            static char* IDB_IF_OS = "\x0c\x00";
            static char* IDB_IF_FCSLEN = "\x0d\x00";
            static char* IDB_IF_TSOFFSET = "\x0e\x00";
            static char* IDB_IF_HARDWARE = "\x0f\x00";
            static char* IDB_IF_TXSPEED = "\x10\x00";
            static char* IDB_IF_RXSPEED = "\x11\x00";
            static char* EPB_EPB_FLAGS = "\x02\x00";
            static char* EPB_EPB_HASH = "\x03\x00";
            static char* EPB_EPB_DROPCOUNT = "\x04\x00";
            static char* NBR_NS_DNSNAME = "\x02\x00";
            static char* NBR_NS_DNSIP4ADDR = "\x03\x00";
            static char* NBR_NS_DNSIP6ADDR = "\x04\x00";
            static char* ISB_ISB_STARTTIME = "\x02\x00";
            static char* ISB_ISB_ENDTIME = "\x03\x00";
            static char* ISB_ISB_IFRECV = "\x04\x00";
            static char* ISB_ISB_IFDROP = "\x05\x00";
            static char* ISB_ISB_FILTERACCEPT = "\x06\x00";
            static char* ISB_ISB_OSDROP = "\x07\x00";
            static char* ISB_ISB_USRDELIV = "\x08\x00";
        };

        struct block
        {
        private:
            char* blockType;
            char* blockLength;

        public:
            block();
            block()
            virtual ~block();
            block& operator=(const block &other);
            block& operator=(block &other);
            block& operator==(const block &other);
            block& operator==(block &other);
        };

        struct sectionHeaderBlock : block
        {

        };

        class PCAPNG
        {
            public:
                PCAPNG()
                PCAPNG(const PCAPNG &other);
                PCAPNG(PCAPNG &&other);
                virtual ~PCAPNG();
                PCAPNG& operator=(const PCAPNG &other);
                PCAPNG& operator=(PCAPNG &other);
                PCAPNG& operator==(const PCAPNG &other);
                PCAPNG& operator==(PCAPNG &other);
            private:


        };
    }

} /* namespace wayne */
