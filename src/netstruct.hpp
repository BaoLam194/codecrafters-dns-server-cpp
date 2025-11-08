#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <arpa/inet.h>

// Default should be network order byte, so need to change to host byte order before changing
struct DNSHeader
{
    uint16_t transactionId;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
};

struct DNSQuestion
{
    std::string qName; // codecrafters.io or google.com, parse later
    uint16_t qType;
    uint16_t qClass;
};
struct DNSAnswer
{
    std::string name; // codecrafters.io or google.com, parse later
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint16_t rdLength;
    std::string rData;
};
struct DNSMessage
{
    DNSHeader header;
    DNSQuestion *questions;
    DNSAnswer *answers;
};

// Parse the name into labels, codecrafters.io -> \x0ccodecrafters\x02io\x00
std::string serializeName(std::string name)
{
    std::string result = "";
    std::string temp = "";
    uint8_t len = 0;
    for (int i = 0; i < name.length(); i++)
    {
        if (name[i] == '.')
        {
            result.push_back(len);
            result += temp;
            len = 0;
            temp = "";
        }
        else if (name[i] != '.')
        {
            len++;
            temp += name[i];
        }
    }
    // Final label
    result.push_back(len);
    result += temp;
    // Add null terminate
    result.push_back('\0');
    return result;
}

// Serialize the message into buffer and current offset len.
void serializeDNSMessage(char *dest, DNSMessage &src, size_t &len)
{
    // Serialize header section
    memcpy(dest + len, &(src.header), sizeof(src.header));
    len += sizeof(src.header);

    // Serialize question section
    size_t numQ = ntohs(src.header.qdCount);
    // Serialize each question
    for (int i = 0; i < numQ; i++)
    {
        DNSQuestion &q = src.questions[i];
        std::string temp = serializeName(q.qName);
        memcpy(dest + len, temp.data(), (size_t)temp.length());
        len += temp.length();
        memcpy(dest + len, &(q.qType), sizeof(uint16_t));
        len += sizeof(uint16_t);
        memcpy(dest + len, &(q.qClass), sizeof(uint16_t));
        len += sizeof(uint16_t);
    }

    // Serialize each answer
    size_t numA = ntohs(src.header.anCount);
    for (int i = 0; i < numA; i++)
    {
        DNSAnswer &a = src.answers[i];
        std::string temp = serializeName(a.name);
        memcpy(dest + len, temp.data(), (size_t)temp.length());
        len += temp.length();
        memcpy(dest + len, &(a.type), sizeof(uint16_t));
        len += sizeof(uint16_t);
        memcpy(dest + len, &(a._class), sizeof(uint16_t));
        len += sizeof(uint16_t);
        memcpy(dest + len, &(a.ttl), sizeof(uint16_t));
        len += sizeof(uint32_t);
        memcpy(dest + len, &(a.rdLength), sizeof(uint16_t));
        len += sizeof(uint16_t);
        memcpy(dest + len, a.rData.data(), (size_t)a.rData.length());
        len += a.rData.length();
    }
}

// Parse the byte buffer into DNSMessage
void parseDNSMessage(DNSMessage &dest, char *src, size_t &len)
{
    // Parse header section, mimic ID, Opcode and RD only, else turn 0 except QR

    memcpy(&dest.header, src + len, sizeof(DNSHeader));
    len += sizeof(DNSHeader);
    // Change from query to reply in flags
    dest.header.flags |= htons(1 << 15);
    // Change bits 1->8, 10 and 11 to 0
    dest.header.flags &= htons(~(0b11111111));
    dest.header.flags &= htons(~(0b11 << 9));
    // qd,ns,ar count got copied normally, just need update ancount
    dest.header.anCount = dest.header.qdCount;
}