
#ifndef SNMPCLIENT_H_
#define SNMPCLIENT_H_

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/utilities.h>
#include <net-snmp/net-snmp-includes.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <SNMPClientException.h>


namespace tmx::utils {

class SNMPClient
{
private:
    netsnmp_session session;
    netsnmp_session *ss;
    netsnmp_pdu    *pdu, *response = NULL;
    netsnmp_variable_list *vars;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
    int _snmp_port;
	std::string _rsuIP;

public:
    /**
     * @brief Construct a new SNMPClient object
     * @param ip RSU IP
     * @param port SNMP port
     */
    SNMPClient(const std::string &rsuIP, uint16_t snmp_port, const std::string &snmp_user, const std::string &securityLevel, const std::string &authPassPhrase);
    /**
     * @brief Send SNMP v3 Get request to an RSU to retrieve data
     * @param oid  OID (Object Identifier) uniquely identify managed objects in a MIB database. Concept refers to: https://en.wikipedia.org/wiki/Management_information_base
     * @return std::string identified by the oid. If SNMP response is not string, exit with failure.
     */
    std::string SNMPGet(const std::string &oid);
    /**
     * @brief Send SNMP v3 Set request to an RSU to write data
     * @param oid OID (Object Identifier) uniquely identify managed objects in a MIB database.
     * @return std::string identified by the oid. If SNMP response is not string, exit with failure.
     */
    bool SNMPSet(const std::string &oid, int32_t value);
    bool SNMPSet(const std::string &oid, u_char type, const void *value, size_t len);
    /** 
     * @brief Retrieve the port used by this SNMP client as an integer.
     * @return The port as expected in a host integer.
     */
    virtual int GetPort() const;
    /** 
     * @brief Retrieve a copy of the RSU IPv4 address.
     * @return std::string with a copy of the constructor input address.
     */
	virtual std::string GetAddress() const;
    ~SNMPClient();
};

} // namespace tmx::utils

#endif /* SNMPCLIENT_H_ */
