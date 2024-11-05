#include "oauth2.h"

#include "Utils.hpp"
#include "Queries.hpp"

#include <drogon/drogon.h>
#include "models/Client.h"

using drogon_model::auth_server::Client;

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
    if (!req.get()->getParameters().contains(client_id))
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
    
    
    std::string res;
	
    
    std::vector r_uris = client->redirect_uris;
    
    if (!req.url_params.get("redirect_uri") || 
        std::find(r_uris.begin(), r_uris.end(), 
        std::string(req.url_params.get("redirect_uri"))) == r_uris.end())
    {
        res = env.render(error_temp, {{"error", "Invalid redirect URI"}});
		auto page = crow::mustache::compile(res);
		return page.render();
    }   
	
	if (!req.url_params.get("scope"))
	{
		res = env.render(error_temp, {{"error", "Scope not found"}});
		auto page = crow::mustache::compile(res);
		return page.render();
	}
	
	auto scope = get_scope(req.url_params.get("scope"));
	for (const auto& el: scope)
	{
		if(!client->scope.contains(el))
		{	
			res = env.render(error_temp, {{"error", "invalid scope"}});
			auto page = crow::mustache::compile(res);
			return page.render();
		}
	}
	    
	crow::query_string query = req.url_params;
    const std::string reqid = gen_random(8);
    
	Request request(reqid, req.raw_url);
	request.create();
	
	std::vector<std::string> client_scope;
	client_scope.insert(
		client_scope.end(), 
		client->scope.begin(), 
		client->scope.end()
	);
    
	json render_json;
	render_json["scope"] = client_scope;
	render_json["reqid"] = reqid;
	
	res = env.render(appr_temp, render_json);
	auto page = crow::mustache::compile(res);
	return page.render();
}