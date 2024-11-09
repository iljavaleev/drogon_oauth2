#include "Utils.hpp"

#include <unordered_set>
#include <string>

#include "models/Client.h"
#include "models/Token.h"
#include "models/ClientGrantType.h"
#include <jwt-cpp/jwt.h>


using namespace drogon_model::auth_server;

const std::string WORKDIR = std::getenv("WORKDIR");

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

drogon::HttpResponsePtr send_error(
    std::string&& message, drogon::HttpStatusCode code)
{
    Json::Value ret;
    ret["error"] = std::move(message);
    auto resp = drogon::HttpResponse::newHttpJsonResponse(ret);
    resp->setStatusCode(code);
    return resp;
}

std::string build_url(std::string base, Json::Value options)
{
    std::ostringstream url;
    url << base << '?';
    
    auto keys = options.getMemberNames();
    for (auto key: keys)
        url << key<< '=' << options[key] << "&";

    std::string uri = url.str();
    uri.pop_back();
    return uri;
}

bool is_subset_of_client_scope(const std::vector<ClientScope>& client_scope,
    const std::unordered_set<std::string>& req_scope)
{
    std::unordered_set<std::string> scopes;
    for (ClientScope s: client_scope)
    {
        scopes.insert(s.getValueOfScope());
    }

    for (const auto& el: req_scope)
	{
		if(!scopes.contains(el))
		{	
			return false;
		}
	}
    return true;
}


std::vector<std::string> decode_client_credentials(
    const std::string& code)
{
    std::string token = code.substr(code.find(' ') + 1);
    size_t pos = token.find(':');
    if(pos == token.npos)
        return  {};
    std::string id{token.substr(0, pos)}, 
        secret{token.substr(pos+1)};
    
    std::string decode_token = drogon::utils::base64Decode(token); 
    
    return {
        drogon::utils::base64Decode(id), 
        drogon::utils::base64Decode(secret) 
    };
}


jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson> get_verifier()
{
    std::ifstream public_key(WORKDIR + "/public.pem");
    std::stringstream buffer;

    buffer << public_key.rdbuf();
    std::string pbk{buffer.str()};
    buffer.clear();

    return jwt::verify().with_type("JWT").
            allow_algorithm(
        jwt::algorithm::rs256(pbk, "", "", ""));
}

