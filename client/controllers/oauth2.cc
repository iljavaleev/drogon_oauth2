#include "Utils.hpp"
#include "Queries.hpp"

#include <drogon/drogon.h>
#include "models/Client.h"
#include "models/RedirectUri.h"
#include "models/ClientScope.h"
#include "models/Token.h"
#include "models/ClientGrantType.h"
#include "models/ClientResponseType.h"
#include "oauth2.h"
#include <algorithm>

const std::string WORKDIR = std::getenv("WORKDIR");

using namespace drogon;
using namespace drogon_model::client;

void oauth2::idx(const HttpRequestPtr &req,
                 std::function<void (const HttpResponsePtr &)> &&callback)
{

    HttpViewData data;
    Json::Value clients(Json::arrayValue);
    clients = get_all_clients(quries::get_full_clients_info);
    data.insert("clients", clients);
    auto resp = HttpResponse::newHttpViewResponse("Index.csp", data);
    callback(resp);
}