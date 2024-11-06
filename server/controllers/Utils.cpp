#include "Utils.hpp"

#include <unordered_set>
#include <string>

#include "models/Client.h"
#include "models/Token.h"
#include "models/ClientGrantType.h"

using drogon_model::auth_server::Client;
using drogon_model::auth_server::Token;


Json::Value get_all_clients(const std::string& query)

{   
    drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    auto future_result = db->execSqlAsyncFuture(query);
    Json::Value clients(Json::arrayValue);
    try
    {
        auto result = future_result.get();
        
        drogon::orm::Result::iterator from{result.begin()}, to{result.end()};
        std::unordered_set<std::string> grant_types;
        std::unordered_set<std::string> response_types;
        std::unordered_set<std::string> scopes;
        std::unordered_set<std::string> redirect_uris;
        std::string prev_cl_id; 
        while(from != to)
        {
            Json::Value client;
            prev_cl_id = (*from)["client_id"].as<std::string>();
            
            Client first_client(*from, -1);
            client = first_client.toJson();
            client["access_token"] = (*from)["access_token"].as<std::string>(); 
            client["refresh_token"] = 
                (*from)["refresh_token"].as<std::string>();

            Json::Value client_grant_types(Json::arrayValue), 
                client_response_types(Json::arrayValue), 
                client_scopes(Json::arrayValue), 
                client_redirect_uris(Json::arrayValue);
            while(1)
            {    
                drogon::orm::Row row = *from;
                if (from != to && row["client_id"].as<std::string>() == 
                    prev_cl_id)
                {
                    grant_types.insert(row["grant_type"].as<std::string>());
                    response_types.insert(
                        row["response_type"].as<std::string>()
                    );
                    scopes.insert(row["scope"].as<std::string>());
                    redirect_uris.insert(row["uri"].as<std::string>());
                    from++;
                }
                else
                {
                    for (auto gt: grant_types)
                        client_grant_types.append(gt);
                    grant_types.clear();
                    client["grant_type"] = client_grant_types;
                    for (auto rt: response_types)
                        client_response_types.append(rt);
                    response_types.clear();
                    client["response_type"] = client_response_types;
                    for (auto s: scopes)
                        client_scopes.append(s);
                    scopes.clear();
                    client["scope"] = client_scopes;
                    for (auto ru: redirect_uris)
                        client_redirect_uris.append(ru);
                    redirect_uris.clear();
                    client["redirect_uri"] = client_redirect_uris;
                    clients.append(client);
                    break;
                }
            }
        }
    }
    catch(const drogon::orm::DrogonDbException &e)
    {
        std::cerr << "error:" << e.base().what() << std::endl;
    }
    return clients;    
}


std::unordered_set<std::string> get_scope(const std::string& scope)
{
    std::unordered_set<std::string> res;
    std::istringstream iss(scope);
    std::string s;
    while (getline(iss, s, ' ')) 
        res.insert(s);
    return res;
}


std::string get_scope(const std::unordered_set<std::string>& scope)
{
    std::ostringstream ss;
    for (const auto& s: scope)
        ss << s << " ";
    std::string res = ss.str();
    res.pop_back();
    return res;
}