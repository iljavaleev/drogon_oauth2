#pragma once

#include <drogon/HttpMiddleware.h>
#include "models/Client.h"
#include <unordered_set>

using namespace drogon;

const std::unordered_set<std::string> 
token_endpoint_auth_methods{"secret_basic", "secret_post", "none"};


class ClientMetadataMW: public HttpMiddleware<ClientMetadataMW>
{
public:
    ClientMetadataMW(){};
    void invoke(const HttpRequestPtr &req,
                MiddlewareNextCallback &&nextCb,
                MiddlewareCallback &&mcb) override
    {
        std::shared_ptr<Json::Value> body;

        auto send_error = [&](std::string&& message, 
            drogon::HttpStatusCode code)
        {
                Json::Value ret;
                ret["error"] = std::move(message);
                auto resp = drogon::HttpResponse::newHttpJsonResponse(ret);
                resp->setStatusCode(code);
                mcb(resp);
        };
        
        try
        {
            body = req->getJsonObject();
        }
        catch(const std::exception& e)
        {
            send_error("request error", drogon::HttpStatusCode::k400BadRequest);
        }
        
        
        if (!(*body).contains("token_endpoint_auth_method"))
            (*body)["token_endpoint_auth_method"] = "secret_basic";
        
        
        if (!token_endpoint_auth_methods.
            contains((*body)["token_endpoint_auth_method"]))
        {
            send_error("invalid_client_metadata", 
                drogon::HttpStatusCode::k400BadRequest);
        }
        
        bool grant_types_contains_auth_code{false}, 
            response_types_contains_code{false};
        if ((*body).contains("grant_types"))
        {
            grant_types_contains_auth_code = 
                (*body)["grant_types"].find("authorization_code") 
                    != grant_types.end();
        }
        
        if ((*body).contains("response_types"))
        {
            response_types_contains_code = 
                (*body)["response_types"].find("code") != response_types.end();
        }
    
        
        if ((*body).contains("grant_types") && 
            (*body).contains("response_types"))
        {
            if (grant_types_contains_auth_code && !response_types_contains_code)
                (*body)["response_types"].append("code");

            if (!grant_types_contains_auth_code && response_types_contains_code)
                (*body)["grant_types"].append("authorization_code");
        }
        else if ((*body).contains("grant_types"))
        {
            if (grant_types_contains_auth_code)
                (*body)["response_types"].append("code");
        }
        else if ((*body).contains("response_types"))
        { 
            if (response_types_contains_code)
                (*body)["grant_types"].append("authorization_code");
        }
        else
        {
            (*body)["response_types"].append("code");
            (*body)["grant_types"].append("authorization_code");
        }
        // we recieve only authorization_code as gt and code as rt
        if ((*body)["grant_types"].size() > 1 || 
            (*body)["response_types"].size() > 1)
        {
            LOG_DEBUG << "invalid gt rt";
            send_error("invalid_client_metadata", 
                drogon::HttpStatusCode::k400BadRequest);
        }

        if (!body.contains("redirect_uris"))
        {
            LOG_DEBUG << "redirect uri lost";
            send_error("invalid_client_metadata", 
                drogon::HttpStatusCode::k400BadRequest);
        }	

        Json::Value redirect_uri(Json::arrayValue);
        
        if (!(*body).contains("redirect_uris") || 
            (*body)["redirect_uris"].empty())
        {
            send_error("invalid_client_metadata", 
                drogon::HttpStatusCode::k400BadRequest);
        }
        
        if (!(*body).contains("client_uri"))
        {
            LOG_DEBUG << "client uri missed";
            send_error("invalid_client_metadata", 
                drogon::HttpStatusCode::k400BadRequest);
        }	

        if (body["client_name"].isString())
            new_client["client_name"]  = (*body)["client_name"];
        
        
        nextCb([mcb = std::move(mcb)](const HttpResponsePtr &resp){
            mcb(resp);
        });
    }
};

#endif