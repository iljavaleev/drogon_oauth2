#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class oauth2 : public drogon::HttpController<oauth2>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(oauth2::idx, "/", Get);
    ADD_METHOD_TO(oauth2::authorize, "/authorize?response_type={}&client_uri={}" 
    "&scope={}&client_id={}&redirect_uri={}&state={}", Get); 
    ADD_METHOD_TO(oauth2::approve, "/approve", Post); 
    ADD_METHOD_TO(oauth2::token, "/token", Post); 
    ADD_METHOD_TO(oauth2::public_key, "/public_key", Post); 
    ADD_METHOD_TO(oauth2::revoke_handler, "/revoke_handler", Post);
    ADD_METHOD_TO(oauth2::register_handler, "/register", Post, "ClientMetadataMW"); 
    ADD_METHOD_TO(oauth2::client_management_handler, 
      "/register/{}", Get, Put, Delete, 
      "AuthorizeConfigurationMW", "ClientMetadataMW");

    METHOD_LIST_END
    void idx(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback);
    void authorize(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback, 
              std::string&& response_type, std::string&& client_uri, 
              std::string&& scope, std::string&& client_id, 
              std::string&& redirect_uri, std::string&& state);
    void approve(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback);
    void token(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback);
    void public_key(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback);
    void revoke_handler(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback);
    void register_handler(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback);
    void client_management_handler(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback, 
              std::string &&client_id);
        
};
