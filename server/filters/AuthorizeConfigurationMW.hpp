#ifndef AuthorizeConfigurationMW_hpp
#define AuthorizeConfigurationMW_hpp

#include <drogon/HttpMiddleware.h>
#include "models/Client.h"
#include "models/Token.h"
#include <unordered_set>


using namespace drogon;
using namespace drogon_model::auth_server;



class AuthorizeConfigurationMW: public HttpMiddleware<AuthorizeConfigurationMW>
{
public:
    AuthorizeConfigurationMW(){};
    void invoke(const HttpRequestPtr &req,
                MiddlewareNextCallback &&nextCb,
                MiddlewareCallback &&mcb) override
    {
        std::string client_id = req->getParameter("client_id");
        drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
        drogon::orm::Mapper<drogon_model::auth_server::Client> client_mapper(db);
        
        auto send_error = [&](std::string&& message, 
            drogon::HttpStatusCode code)
        {
                Json::Value ret;
                ret["error"] = std::move(message);
                auto resp = drogon::HttpResponse::newHttpJsonResponse(ret);
                resp->setStatusCode(code);
                mcb(resp);
        };
        Client client;
        try
        {
            client = client_mapper.findByPrimaryKey(client_id);
        }
        catch(const std::exception& e)
        {
            send_error("client not found", 
                drogon::HttpStatusCode::k400BadRequest);
        }
        Token client_token = client.getToken();

        auto headers = req->getHeaders();
        headers["Authorization"]; 
        if (!headers.contains("Authorization") 
            || headers["Authorization"].empty())
        {   
            send_error("authorization header error", 
                drogon::HttpStatusCode::k403Forbidden);
        }
        std::string req_token;
        std::string bearer = 
            headers["Authorization"].substr(0, authorization.find(' '));
        for (char& c: bearer)
            c = tolower(c);
        if (bearer == "bearer")
            req_token = authorization.substr(authorization.find(' ') + 1);
        else
        {
            send_error("token bearer error", 
                drogon::HttpStatusCode::k401Unauthorized);
        }

        if (req_token != client_token.getAccessToken())
        {
            send_error("token validation error", 
                drogon::HttpStatusCode::k403Forbidden);
        }

        std::shared_ptr<Json::Value> body = req->getJsonObject();
        (*body)["client"] = client.toJson();
    
        nextCb([mcb = std::move(mcb)](const HttpResponsePtr &resp){
            mcb(resp);
        });
    }
};

#endif