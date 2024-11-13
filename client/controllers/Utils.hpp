#ifndef Utils_hpp
#define Utils_hpp

#include <drogon/drogon.h>
#include <unordered_set>
#include <jwt-cpp/jwt.h>
#include "models/ClientScope.h"

using namespace drogon_model::client; 

Json::Value get_all_clients(const std::string& query);
std::unordered_set<std::string> get_scope(const std::string& scope);
std::string get_scope(const std::unordered_set<std::string>& scope);
drogon::HttpResponsePtr send_error(
    std::string&& message, drogon::HttpStatusCode code);
std::string build_url(std::string base, Json::Value options);
std::vector<std::string> decode_client_credentials( const std::string& code);
bool is_subset_of_client_scope(const std::vector<ClientScope>& client_scope,
    const std::unordered_set<std::string>& req_scope);
jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson> get_verifier();
#endif