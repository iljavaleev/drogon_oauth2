#include "oauth2.h"
#include "models/Client.h"
#include "models/Token.h"

void oauth2::idx(const HttpRequestPtr &req,
                 std::function<void (const HttpResponsePtr &)> &&callback)
{
   
    std::shared_ptr<Json::Value> jv = req->getJsonObject();
    if (!jv)
        LOG_WARN << "fucked up";
    HttpViewData data;
    std::unordered_map<std::string, std::string, drogon::utils::internal::SafeStringHash> mp;
    for (auto n: jv->getMemberNames())
    {
        std::cout << n << " " << (*jv)[n];
        mp.insert({n, (*jv)[n].asString()});
    }
    std::vector<std::string> e = {"odin", "dva"};
   
    data.insert("title", "ListParameters");
    data.insert("parameters", mp);
    data.insert("else", e);
 
    drogon::orm::DbClientPtr db = drogon::app().getDbClient("default");
    drogon::orm::Mapper<drogon_model::auth_server::Client> aa(db);
    auto users = aa.findAll();
    for (auto u: users)
    {
        std::cout << *(u.getClientId()) << std::endl;
        std::cout << *(u.getClientUri()) << std::endl;
        std::vector<drogon_model::auth_server::Token> t = u.getToken(db);
        drogon_model::auth_server::Token tt = t[0];
        std::cout << *(tt.getAccessToken()) << std::endl;

    }

    data.insert("client", users.at(0).toJson());
    // auto resp = HttpResponse::newHttpJsonResponse(a);
    auto resp = HttpResponse::newHttpViewResponse("ListParameters.csp", data);
    callback(resp);
}