#include "SNMPClient.h"

namespace tmx {
namespace utils {

SNMPClient::SNMPClient(const std::string &rsuIP, uint16_t snmp_port, const std::string &snmp_user, const std::string &securityLevel, const std::string &authPassPhrase)
    : _snmp_port(snmp_port)
    , _rsuIP(rsuIP)
{
    std::string ip_port_string = rsuIP + ":" + std::to_string(snmp_port);
    char *ip_port = &ip_port_string[0];
    init_snmp("snmpclient");
    snmp_sess_init(&session);
    session.peername = ip_port;
    session.version = SNMP_VERSION_3;
    session.securityName = (char *)snmp_user.c_str();
    session.securityNameLen = snmp_user.length();
    if (securityLevel == "authPriv") {
        session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
    }
    else if (securityLevel == "authNoPriv") {
        session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
    }
    else session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
    session.securityAuthProto = snmp_duplicate_objid(usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN);
    session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
    session.securityAuthKeyLen = USM_AUTH_KU_LEN;
    if (generate_Ku(session.securityAuthProto,
                    session.securityAuthProtoLen,
                    (u_char *)authPassPhrase.c_str(),authPassPhrase.length(),
                    session.securityAuthKey,
                    &session.securityAuthKeyLen) != SNMPERR_SUCCESS)
    {
        std::string errMsg = "Error generating Ku from authentication pass phrase. \n";
        throw SNMPClientException(errMsg);
    }
    ss = snmp_open(&session);
    if (!ss)
    {
        std::string errMsg = "Cannot open SNMP session. \n";
        throw SNMPClientException(errMsg);
    }
    else
    {
        fprintf(stdout, "snmp session is open.\n");
    }
}

std::string SNMPClient::SNMPGet(const std::string &req_oid)
{
    std::string result = "";
    auto pdu = snmp_pdu_create(SNMP_MSG_GET);
    if (!snmp_parse_oid(req_oid.c_str(), anOID, &anOID_len))
    {
        snmp_perror(req_oid.c_str());
        std::string errMsg = "OID could not be created from input:" + req_oid;
        throw SNMPClientException(errMsg);
        SOCK_CLEANUP;
    }
    snmp_add_null_var(pdu, anOID, anOID_len);
    auto status = snmp_synch_response(ss, pdu, &response);
    if (!response)
    {
        throw SNMPClientException("No response for SNMP Get request!");
    }
    else if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)
    {
        // SUCCESS: Return the response as result
        for (auto vars = response->variables; vars; vars = vars->next_variable)
        {
            if (vars->type == ASN_OCTET_STR)
            {
                result = reinterpret_cast<char *>(vars->val.string);
            }
            else
            {
                throw SNMPClientException("Received respones type is not a string");
            }
        }
    }
    else
    {
        // FAILURE: Print what went wrong!
        std::string errMsg = snmp_errstring(response->errstat);
        throw SNMPClientException("Error in packet. Reason:" + errMsg);
    }
    if (response)
        snmp_free_pdu(response);
    return result;
}

bool SNMPClient::SNMPSet(const std::string &oid, int32_t value)
{
	return SNMPClient::SNMPSet(oid, ASN_INTEGER, (const void *)&value, sizeof(value));
}

bool SNMPClient::SNMPSet(const std::string &oid, u_char type, const void *value, size_t len)
{
    bool rc = true;
    static int quiet = 0;
    int             arg;
    int             count;
    int             current_name = 0;
    int             current_type = 0;
    int             current_value = 0;
    char           *names[SNMP_MAX_CMDLINE_OIDS];
    char            types[SNMP_MAX_CMDLINE_OIDS];
    char           *values[SNMP_MAX_CMDLINE_OIDS];
    int             status;
    int             failures = 0;
    int             exitval = 0;
    auto pdu = snmp_pdu_create(SNMP_MSG_SET);

    // if (!snmp_parse_oid(oid.c_str(), anOID, &anOID_len))
    // {
    //     snmp_perror(oid.c_str());
    //     std::string errMsg = "OID could not be created from input:" + oid;
    //     throw SNMPClientException(errMsg);
    //     SOCK_CLEANUP;
    // }
    for (count = 0; count < current_name; count++) {
        if (snmp_parse_oid(names[count], anOID, &anOID_len) == NULL) {
            snmp_perror(names[count]);
            failures++;
        } else
            if (snmp_add_var
                (pdu, anOID, anOID_len, types[count], values[count])) {
            snmp_perror(names[count]);
            failures++;
        }
    }

    if (failures) {
        snmp_close(ss);
        SOCK_CLEANUP;
        exit(1);
    }
    
    // snmp_add_null_var(pdu, anOID, anOID_len);
    // snmp_pdu_add_variable(pdu, anOID, anOID_len, type, value, len);

	auto status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {
        if (response->errstat == SNMP_ERR_NOERROR) {
            if (!quiet) {
                for (vars = response->variables; vars;
                     vars = vars->next_variable)
                    print_variable(vars->name, vars->name_length, vars);
            }
        } else {
            fprintf(stderr, "Error in packet.\nReason: %s\n",
                    snmp_errstring(response->errstat));
            if (response->errindex != 0) {
                fprintf(stderr, "Failed object: ");
                for (count = 1, vars = response->variables;
                     vars && (count != response->errindex);
                     vars = vars->next_variable, count++);
                if (vars)
                    fprint_objid(stderr, vars->name, vars->name_length);
                fprintf(stderr, "\n");
            }
            exitval = 2;
        }
    } else if (status == STAT_TIMEOUT) {
        fprintf(stderr, "Timeout: No Response from %s\n",
                session.peername);
        exitval = 1;
    } else {                    /* status == STAT_ERROR */
        snmp_sess_perror("snmpset", ss);
        exitval = 1;
    }

    if (response)
        snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;
    return exitval;
}

int SNMPClient::GetPort() const
{
    return _snmp_port;
}

std::string SNMPClient::GetAddress() const
{
    return _rsuIP;
}

SNMPClient::~SNMPClient()
{
    fprintf(stdout, "Closing snmp session\n");
    snmp_close(ss);
}

}} // namespace tmx::utils
