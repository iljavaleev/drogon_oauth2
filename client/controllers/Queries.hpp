#ifndef Queries_hpp
#define Queries_hpp

#include <string>
namespace quries
{

inline const std::string get_full_clients_info = 
    "select c.*, t.access_token, t.refresh_token, "
    "cgt.grant_type, crt.response_type, s.scope, ru.uri from client c "
    "join token t on c.client_id=t.client_id join client_grant_type cgt "
    "on cgt.client_id = c.client_id join client_response_type crt "
    "on crt.client_id = c.client_id join client_scope s "
    "on s.client_id = c.client_id join redirect_uri ru "
    "on ru.client_id = c.client_id";
};
#endif