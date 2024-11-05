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

    METHOD_LIST_END
    void idx(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback);
    void authorize(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback, 
              std::string&& response_type, std::string&& client_uri, 
              std::string&& scope, std::string&& client_id, 
              std::string&& redirect_uri, std::string&& state);
};
