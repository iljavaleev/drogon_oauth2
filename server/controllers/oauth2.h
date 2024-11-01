#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class oauth2 : public drogon::HttpController<oauth2>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(oauth2::idx, "/", Post); 

    METHOD_LIST_END
    void idx(const HttpRequestPtr &req,
              std::function<void (const HttpResponsePtr &)> &&callback);
};