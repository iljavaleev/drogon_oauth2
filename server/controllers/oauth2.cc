#include "oauth2.h"

#include "Utils.hpp"
#include "Queries.hpp"

#include <drogon/drogon.h>
#include "models/Client.h"
#include "models/RedirectUri.h"
#include "models/ClientScope.h"
#include "models/Request.h"
#include <algorithm>

using namespace drogon_model::auth_server;

void oauth2::idx(const HttpRequestPtr &req,
                 std::function<void (const HttpResponsePtr &)> &&callback)
{
    // std::unordered_map<std::string, std::string, drogon::utils::internal::SafeStringHash> mp;
    // drogon::orm::Mapper<drogon_model::auth_server::Client> client_mapper(db);
    // auto clients = client_mapper.findAll();
    
    HttpViewData data;
    Json::Value clients(Json::arrayValue);
    clients = get_all_clients(quries::get_full_clients_info);
    data.insert("clients", clients);
    auto resp = HttpResponse::newHttpViewResponse("Index.csp", data);
    callback(resp);
}


 void oauth2::authorize(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback, 
              std::string&& response_type, std::string&& client_uri, 
              std::string&& scope, std::string&& client_id, 
              std::string&& redirect_uri, std::string&& state)
{

    HttpViewData data;
    drogon::HttpResponsePtr resp;
    if (!req.get()->getParameters().contains("client_id"))
    {
        data.insert("error", "Unknown client");
        resp = HttpResponse::newHttpViewResponse("Error.csp", data);
        callback(resp);
    }

    drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<drogon_model::auth_server::Client> client_mapper(db);
    Client client;
    try
    {
        client = client_mapper.findByPrimaryKey(client_id);
    }
    catch(const std::exception& e)
    {
        LOG_DEBUG << e.what();
        data.insert("error", "Unknown client");
        resp = HttpResponse::newHttpViewResponse("Error.csp", data);
        callback(resp);
    }
    
    auto uris = client.getRedirectUri(db);
    auto client_red_iri = 
        std::find_if(uris.begin(), uris.end(), [&](const RedirectUri& uri)
        {
            return uri.getValueOfUri() == redirect_uri;
        }
    );

    if (!req.get()->getParameters().contains("redirect_uri") || 
        client_red_iri == uris.end())
    {
        data.insert("error", "Invalid redirect URI");
        resp = HttpResponse::newHttpViewResponse("Error.csp", data);
        callback(resp);
    }

    if (!req.get()->getParameters().contains("scope"))
    {
        data.insert("error", "Scope not found");
        resp = HttpResponse::newHttpViewResponse("Error.csp", data);
        callback(resp);
    }

    std::vector<ClientScope> client_scopes_inst = client.getScope(db);   
    std::unordered_set<std::string> client_scopes;
    for (ClientScope s: client_scopes_inst)
    {
        client_scopes.insert(s.getValueOfScope());
    }
    client_scopes_inst.clear();
    std::unordered_set<std::string> req_scopes = get_scope(scope);
    
    for (const auto& el: req_scopes)
	{
		if(!client_scopes.contains(el))
		{	
			data.insert("error", "Scope not found");
            resp = HttpResponse::newHttpViewResponse("Error.csp", data);
            callback(resp);
		}
	}

    std::string query = req->getQuery();
    LOG_WARN << query;
    const std::string reqid = drogon::utils::genRandomString(12);
    Request request;
    request.setQuery(query);
    request.setRequestId(reqid);
    db->execSqlAsync(request.sqlForInserting(),
                    [](const drogon::orm::Result &result) 
                    {
                        LOG_WARN << "request created";
                    },
                    [](const drogon::orm::DrogonDbException &e) 
                    {
                        std::cerr << "error:" << e.base().what() << std::endl;
                    });

    
    Json::Value render_scope(Json::arrayValue);
    
    for (auto s: req_scopes)
    {
        render_scope.append(s);
    }
    data.insert("scope", render_scope);
    data.insert("reqid", reqid);
    resp = HttpResponse::newHttpViewResponse("Approve.csp", data);
    callback(resp);
}