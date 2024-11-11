#include "oauth2.h"

#include "Utils.hpp"
#include "Queries.hpp"

#include <drogon/drogon.h>
#include "models/Client.h"
#include "models/RedirectUri.h"
#include "models/ClientScope.h"
#include "models/Request.h"
#include "models/Code.h"
#include "models/Token.h"
#include "models/ProtectedResource.h"
#include "models/ClientGrantType.h"
#include "models/ClientResponseType.h"
#include <algorithm>

const std::string WORKDIR = std::getenv("WORKDIR");


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
    auto req_scopes = get_scope(scope);
    if (!is_subset_of_client_scope(client_scopes_inst, req_scopes))
	{
        data.insert("error", "Scope not found");
        resp = HttpResponse::newHttpViewResponse("Error.csp", data);
        callback(resp);
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
    auto req_scopes = get_scope(scope);
    for (auto s: req_scopes)
    {
        render_scope.append(s);
    }
    data.insert("scope", render_scope);
    data.insert("reqid", reqid);
    resp = HttpResponse::newHttpViewResponse("Approve.csp", data);
    callback(resp);
}


void oauth2::approve(const HttpRequestPtr &req, 
    std::function<void (const HttpResponsePtr &)> &&callback)
{
    // парсим тело запроса
    drogon::MultiPartParser form_parcer;
    form_parcer.parse(req);
    auto form = form_parcer.getParameters();
   
    if (!form.contains("reqid"))
        callback(send_error(
            "No matching authorization request", 
            drogon::HttpStatusCode::k403Forbidden));

    std::string reqid = form.at("reqid");
    
	drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<Request> request_mapper(db);
    Request request;
    try
    {
        request = request_mapper.findByPrimaryKey(reqid);
    }
    catch(const std::exception& e)
    {
        callback(send_error(
            "No matching authorization request", 
            drogon::HttpStatusCode::k403Forbidden));
    }
     
	std::string raw_query(request.getValueOfQuery());
    db->execSqlAsync(request.sqlForDeletingByPrimaryKey(),
                [](const drogon::orm::Result &result) 
                {
                    LOG_WARN << "request deleted";
                },
                [](const drogon::orm::DrogonDbException &e) 
                {
                    std::cerr << "error:" << e.base().what() << std::endl;
                });
    
	std::unordered_set<std::string> form_scope;
	std::string sc;
	for (const auto& p: form)
	{
		if (p.first.find("scope_") != p.first.npos)
		{
			sc = p.first.substr(p.first.find("_") + 1);
			form_scope.insert(sc);
		}
	}
	// parse query
    // drogon::
    std::unordered_map<std::string, std::string> query;
	///
    std::string client_id{query.at("client_id")};
	drogon::orm::Mapper<Client> client_mapper(db);
    Client client;
    std::string url_parsed;
    
    auto send_response = [&](std::string&& message){
        url_parsed = build_url(query.at("redirect_uri"), 
				{ "error", std::move(message)});
		auto resp = drogon::HttpResponse::newRedirectionResponse(
            std::move(url_parsed)
        );
        callback(resp);
    };

    try
    {
        client = client_mapper.findByPrimaryKey(client_id);
    }
    catch(const std::exception& e)
    {
        send_response("denied access");
    }
    
	if(scope.empty())
		send_response("denied access");
	
    std::vector<ClientScope> client_scope_inst = client.getScope();
    

	if (!is_subset_of_client_scope(client_scope_inst, form_scope))
        send_response("invalid scope");
	
	if ((form.contains("approve") && form.at("approve").empty()) || 
		form.contains("deny"))
	{
		send_response("denied access");
	}
	
	if (strcmp(query.get("response_type"), "code") != 0)
    {
        send_response("unsupported_response_type");
    } 
	
    std::string code = drogon::utils::genRandomString(12);
    drogon::orm::Mapper<Code> code_mapper(db);
	
    Code code_inst;
    code_inst.setCode(code);
    code_inst.setQuery(raw_query);
    code_inst.setScope(get_scope(form_scope));
	
	db->execSqlAsync(code.sqlForInserting(),
                [](const drogon::orm::Result &result) 
                {
                    LOG_WARN << "code created";
                },
                [](const drogon::orm::DrogonDbException &e) 
                {
                    std::cerr << "error:" << e.base().what() << std::endl;
                });
    
    Json::Value ret;
    ret["code"] = std::move(code);
    ret["state"] = std::move(query.at("state"));
    url_parsed = build_url(query.get("redirect_uri"), ret);
    auto resp = drogon::HttpResponse::newRedirectionResponse(
        std::move(url_parsed));
    callback(resp);
}


void oauth2::token(const HttpRequestPtr &req, 
    std::function<void (const HttpResponsePtr &)> &&callback)
{
    
    auto headers = req->getHeaders();
    std::string client_id, client_secret;
    if (!headers.contains("authorization"))
	{
		std::string auth = auth_it->second;
		std::vector<std::string> client_credentials = 
			decode_client_credentials(auth);
		if (client_credentials.empty())
            callback(
                send_error("invalid_client", 
                drogon::HttpStatusCode::k401Unauthorized));
		client_id = client_credentials.at(0);
		client_secret = client_credentials.at(1);
	}
	// Check how it works
    drogon::MultiPartParser form_parcer;
    form_parcer.parse(req);
    auto body = form_parcer.getParameters();
	if(body.contains("client_id"))
	{
		if (!client_id.empty())
			callback(
                send_error("invalid_client", 
                drogon::HttpStatusCode::k401Unauthorized));
		client_id = body["client_id"];
		client_secret = body["client_secret"];
	}
	drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<Client> client_mapper(db);
    Client client;
    Token old_token; 
    try
    {
        client = client_mapper.findByPrimaryKey(client_id);
    }
    catch(const std::exception& e)
    {
        callback(send_error("invalid_client", 
            drogon::HttpStatusCode::k401Unauthorized));
    }
    
	if (client.getValueOfClientSecret() != client_secret) 
		callback(send_error("invalid_client", 
            drogon::HttpStatusCode::k401Unauthorized));
	
	if (!body.contains("grant_type") || 
		!(body.at("grant_type") == "authorization_code" ||
		body.at("grant_type") == "refresh_token")) 
    {
        callback(send_error("invalid_client", 
            drogon::HttpStatusCode::k400BadRequest));
    }
	
	std::string scope;
	if (body.at("grant_type") == "authorization_code")
	{
		if (!body.contains("code"))
        {
            callback(send_error("invalid_grant", 
                drogon::HttpStatusCode::k400BadRequest));
        }
		
        drogon::orm::Mapper<Code> code_mapper(db);
        Code cod; 
        try
        {
           cod = code_mapper.findByPrimaryKey(body.at("code"));
        }
        catch(const std::exception& e)
        {
            callback(send_error("invalid_grant", 
                drogon::HttpStatusCode::k400BadRequest));
        }
        
		scope = cod.getValueOfScope();
		
        db->execSqlAsync
        (
                cod.sqlForDeletingByPrimaryKey(body.at("code")),
                [](const drogon::orm::Result &result) 
                {
                    LOG_WARN << "code deleted";
                },
                [](const drogon::orm::DrogonDbException &e) 
                {
                    std::cerr << "error:" << e.base().what() << std::endl;
                }
        );
        
		std::string raw_query = cod.getValueOfQuery();	
        // parse query
        std::unordered_map<std::string, std::string> query;
		if (query.get("client_id") != client_id)
        {
             callback(send_error("invalid_grant", 
                drogon::HttpStatusCode::k400BadRequest));
        }
			
	}
	else if (body.at("grant_type") == "refresh_token")
	{
		if (!body.contains("refresh_token"))
        {
            callback(send_error("invalid_grant", 
                drogon::HttpStatusCode::k400BadRequest));
        }
		
		try
		{
			get_verifier().verify(jwt::decode(body.at("refresh_token")));
		}
		catch(const std::exception& e)
		{
			LOG_WARN << "wrong refresh token"; 
			callback(send_error("invalid_grant", 
                drogon::HttpStatusCode::k400BadRequest));
		}
		
        old_token = client.getToken(db);
		auto old_refresh_token =old_token.getValueOfRefreshToken();
			Token::get(body.at("refresh_token"), "refresh_token");

        // исправить на сравнение по хэшу 
        if (!body.contains("refresh_token") ||  
            std::hash<std::string>{}(body.at("refresh_token")) != 
            old_refresh_token)
        {
            LOG_WARN <<  "refresh token db problem";
            db->execSqlAsync
            (
                old_token.sqlForDeletingByPrimaryKey(old_token.getValueOfId()),
                [](const drogon::orm::Result &result) 
                {
                    LOG_WARN << "token was deleted";
                },
                [](const drogon::orm::DrogonDbException &e) 
                {
                    std::cerr << "error:" << e.base().what() << std::endl;
                }
            );
            callback(send_error("invalid_grant", 
                drogon::HttpStatusCode::k400BadRequest));
        }
        auto decoded = jwt::decode(old_refresh_token);
		scope = decoded.get_payload_claim("scope").to_string();
	}
	const auto now = std::chrono::system_clock::now();
	const auto exp = now + std::chrono::days(10);
    std::ifstream private_key(WORKDIR + "/key.pem");
    std::stringstream buffer;
    
    buffer << private_key.rdbuf();
    std::string prk{buffer.str()};
    buffer.clear();
    
    using namespace std::literals; 
    const std::time_t expire = std::chrono::system_clock::to_time_t(exp);
    auto access_token = jwt::create()
		.set_type("JWT")
		.set_algorithm("RS256")
		.set_issuer(server_uri)
		.set_audience(resource.resource_uri)
		.set_payload_claim("expire", 
			jwt::claim(std::to_string(expire)))
		.set_payload_claim("scope", 
			jwt::claim(scope))
		.set_id("authserver")
		.sign(jwt::algorithm::rs256("", prk, "", ""));

	auto refresh_token = jwt::create()
		.set_type("JWT")
		.set_algorithm("RS256")
		.sign(jwt::algorithm::rs256("", prk, "", ""));
	
	Json::Value to_update_token = old_token.toJson();
    to_update_token["access_token"] = std::hash<std::string>{}(access_token);
    to_update_token["refresh_token"] = std::hash<std::string>{}(refresh_token);
    to_update_token["access_token_expire"] = std::to_string(expire);
    to_update_token["scope"] = scope;
    
    try
    {
        old_token.updateByJson(to_update_token);
    }
    catch(const std::exception& e)
    {
        LOG_WARN << e.what();
    }
    
    
	Json::Value res_resp = { 
		{"access_token", access_token}, 
		{"token_type", "Bearer"},
		{"access_token expire", std::format("{:%Y%m%d%H%M}", exp)},
		{"refresh_token", refresh_token },
		{"scope", scope } 
	};
	auto resp = HttpResponse::newHttpJsonResponse(res_resp);
	callback(resp);
}


void oauth2::public_key(const HttpRequestPtr &req, 
    std::function<void (const HttpResponsePtr &)> &&callback)
{
    drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<ProtectedResource> resource_mapper(db);
    std::shared_ptr<Json::Value> body_ptr;
    
    try
	{
		body_ptr = req->getJsonObject();
	}
	catch(...)
	{
        callback(send_error(
            "parse body problem", 
            drogon::HttpStatusCode::k400BadRequest));
	}
	
	if ((*body_ptr)["resource"] == Json::Value::nullSingleton())
	{
		callback(send_error(
            "resource problem", 
            drogon::HttpStatusCode::k400BadRequest));
	}

    std::string resource_id = drogon::utils::base64Decode(*body["resource"]);
    ProtectedResource resource;
    
    try
    {
        resource_mapper.findByPrimaryKey(resource_id);
    }
    catch(const std::exception& e)
    {
        callback(send_error(
            "resource problem", 
            drogon::HttpStatusCode::k400BadRequest));
    }
    
	std::ifstream public_key(WORKDIR + "/public.pem");
    std::stringstream buffer;
	buffer << public_key.rdbuf();
    std::string pbk{buffer.str()};

    Json::Value ret;
	ret["public_key"] = std::move(pbk);
	auto resp = HttpResponse::newHttpJsonResponse(ret);
	callback(resp);
}


void oauth2::revoke_handler(const HttpRequestPtr &req, 
    std::function<void (const HttpResponsePtr &)> &&callback)
{
    HttpResponse resp;
	

    auto headers = req->getHeaders();
    std::string client_id, client_secret;
    if (!headers.contains("authorization"))
	{
		std::string auth = auth_it->second;
		std::vector<std::string> client_credentials = 
			decode_client_credentials(auth);
		if (client_credentials.empty())
            callback(
                send_error("invalid_client", 
                drogon::HttpStatusCode::k401Unauthorized));
		client_id = client_credentials.at(0);
		client_secret = client_credentials.at(1);
	}
	// Check how it works
    drogon::MultiPartParser form_parcer;
    form_parcer.parse(req);
    auto body = form_parcer.getParameters();

	if(body.contains("client_id"))
	{
		if (!client_id.empty())
			callback(
                send_error("invalid_client", 
                drogon::HttpStatusCode::k401Unauthorized));
		client_id = body["client_id"];
		client_secret = body["client_secret"];
	}
	drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<Client> client_mapper(db);
	
	Client client;
    Token old_token; 
    try
    {
        client = client_mapper.findByPrimaryKey(client_id);
    }
    catch(const std::exception& e)
    {
        callback(send_error("invalid_client", 
            drogon::HttpStatusCode::k401Unauthorized));
    }
    
	if (client.getValueOfClientSecret() != client_secret) 
		callback(send_error("invalid_client", 
            drogon::HttpStatusCode::k401Unauthorized));
	
	std::string req_token{body["token"]}, type{body["type"]};
    Token old_token_inst = client.getToken();
    Json::Value j_old_token_inst = old_token_inst.toJson();
    
    std::string old_token_hash;
    if (type == "access_token")
        old_token_hash = old_token_inst.getValueOfAccessToken();
    else
        old_token_hash = old_token_inst.getValueOfRefreshToken();

	if (std::hash<std::string>{}(req_token) != old_token_hash)
	{
		if (type == "access_token")
        {
            j_old_token_inst["access_token"] = "";
        }
		else
        {
            db->execSqlAsync
            (
                old_token_inst.sqlForDeletingByPrimaryKey(
                    old_token_inst.getValueOfId()),
                [](const drogon::orm::Result &result) 
                {
                    LOG_WARN << "token deleted";
                },
                [](const drogon::orm::DrogonDbException &e) 
                {
                    std::cerr << "error:" << e.base().what() << std::endl;
                }
            );
            resp.setStatusCode = drogon::HttpStatusCode::k204NoContent;
            callback(resp);
           
        }
	}
    
    try
    {
        old_token_inst.updateByJson(j_old_token_inst);
    }
    catch(...)
    {
        LOG_WARN << "error deleting token";
    }
    
	resp.setStatusCode = drogon::HttpStatusCode::k204NoContent;
    callback(resp);
}

void oauth2::register_handler(const HttpRequestPtr &req, 
    std::function<void (const HttpResponsePtr &)> &&callback)
{
	std::shared_ptr<Json::Value> j_req = req->getJsonObject();
	std::string client_id = drogon::utils::genRandomString(12);
    (*j_req)["client_id"] = client_id;
	(*j_req)["client_id_created_at"] = 
		std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    (*j_req)["client_id_expires_at"] = 0;
    (*j_req)["client_secret"] = drogon::utils::genRandomString(16);
    (*j_req)["registration_access_token"] = drogon::utils::genRandomString(16);
	(*j_req)["registration_client_uri"] = std::format(
		"http://{}:{}/register/{}", 
		std::getenv("SERVER"), 
		std::getenv("SERVER_PORT"), 
		new_client.client_id);
	
    Json::Value j_req_copy(*j_req);

    drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<Client> client_mapper(db);
    {
        drogon::orm::Mapper<ClientScope> scope_mapper(db);
        ClientScope scope;
        scope.setClientId(client_id);
        scope.setScope(j_req_copy["scope"]);
        try
        {
            scope_mapper.insert(scope);
        }
        catch(const std::exception& e)
        {
           LOG_WARN << e.what();
        }
        j_req_copy.removeMember("scope");
    }
    {
        drogon::orm::Mapper<ClientGrantType> grant_type_mapper(db);
        ClientGrantType gt;
        gt.setClientId(client_id);
        
        j_req_copy["grant_types"].isString() ? 
            gt.setGrantType(j_req_copy["grant_types"]) : 
                gt.setGrantType(j_req_copy["grant_types"][0]);
        try
        {
            grant_type_mapper.insert(gt);
        }
        catch(const std::exception& e)
        {
           LOG_WARN << e.what();
        }
        j_req_copy.removeMember("grant_types");
    }   
    {
        drogon::orm::Mapper<ClientResponseType> response_type_mapper(db);
        ClientResponseType rt;
        rt.setClientId(client_id);
        j_req_copy["response_types"].isString() ? 
            rt.setResponseType(j_req_copy["response_types"]) : 
                rt.setResponseType(j_req_copy["response_types"][0]);
        try
        {
           response_type_mapper.insert(rt);
        }
        catch(const std::exception& e)
        {
           LOG_WARN << e.what();
        }
        j_req_copy.removeMember("response_types");
    }
    {
        drogon::orm::Mapper<RedirectUri> redirect_uri_mapper(db);
        RedirectUri ru;
        ru.setClientId(client_id);
        if (j_req_copy["redirect_uris"].isString())
        {
            ru.setResponseType(j_req_copy["redirect_uris"]);
            try
            {
                redirect_uri_mapper.insert(ru);
            }
            catch(const std::exception& e)
            {
                LOG_WARN << e.what();
            }
        } 
        else
        {
            for (auto uri: j_req_copy["redirect_uris"])
            {
                ru.setResponseType(uri);
                try
                {
                    redirect_uri_mapper.insert(ru);
                }
                catch(const std::exception& e)
                {
                    LOG_WARN << e.what();
                }
            }
        }
        j_req_copy.removeMember("redirect_uris");
    }
    drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<Client> client_mapper(db);
    Client new_client(j_req_copy);
    
    try
    {
        client_mapper.insert(new_client);
    }
    catch(const std::exception& e)
    {
        LOG_WARN << e.what();
    }
    
    auto resp = HttpResponse::newHttpJsonResponse(*j_req);
    resp->setStatusCode(drogon::HttpStatusCode::k201Created);
	callback(resp);
}

void oauth2::client_management_handler(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback, 
              std::string &&client_id)
{
	std::shared_ptr<Json::Value> body = req->getJsonObject();
    drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<drogon_model::auth_server::Client> client_mapper(db);
	if (req->getMethod() == drogon::HttpMethod::Get)
	{
        Json::Value client = (*body)["client"];
		client["client_secret"] = drogon::utils::genRandomString(12);
		client["registration_access_token"] = drogon::utils::genRandomString(16);
		Client new_client(client);
        try
        {
            client_mapper.insert(new_client);
        }
        catch(const std::exception& e)
        {
            LOG_WARN << e.what();
        }
		
		auto resp = HttpResponse::newHttpJsonResponse(client);
        callback(resp);
	}
	else if (req->getMethod() == drogon::HttpMethod::Put)
	{

		Json::Value client = (*body)["client"];
        (*body).removeMember("client");
         Client new_client(client);
        
        bool client_id_varif = 
            ((*body).find("client_id") != (*body).end()) && 
            (body["client_id"] == client_id);
		bool client_secret_varif = 
            ((*body).find("client_secret") != (*body).end()) && 
            (body["client_secret"] == client.client_secret);
		
		if (!(client_id_varif && client_secret_varif))
		{
			LOG_WARN << "PUT; client varification error";
			send_error("invalid_client_metadata", 
                drogon::HttpStatusCode::k400BadRequest);
		}

		Json::Value result_client;
		// check fields exists
        result_client["token_endpoint_auth_method"] = 
			 (*body)["token_endpoint_auth_method"];
        result_client["redirect_uris"] = (*body)["redirect_uris"];
		result_client["client_uri"] = (*body)["client_uri"];
		result_client["scope"] = (*body)["scope"];
		result_client["grant_types"] = (*body)["grant_types"];
		result_client["response_types"] = (*body)["response_types"];
		result_client["client_name"] = (*body)["client_name"];
		
		new_client.updateByJson(result_client);
        try
        {
            client_mapper.update(new_client);
        }
        catch(const std::exception& e)
        {
            LOG_WARN << e.what();
        }

		auto resp = HttpResponse::newHttpJsonResponse(client);
        callback(resp);
	}
	else if (req->getMethod() == drogon::HttpMethod::Delete)
	{
        Json::Value client = (*body)["client"];
        (*body).removeMember("client");
        drogon::orm::Mapper<drogon_model::auth_server::Token> token_mapper(db);
		try
		{
			token_mapper.deleteBy();
            client_mapper.deleteByPrimaryKey(client_id);
		}
		catch(const std::exception& e)
		{
			LOG_WARN << e.what();
		}
		auto resp = HttpResponse::newHttpJsonResponse(client);
        resp->setStatusCode(drogon::HttpStatusCode::k204NoContent);
        callback(resp);
	}
}
