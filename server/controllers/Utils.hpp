#ifndef Utils_hpp
#define Utils_hpp

#include <drogon/drogon.h>
#include <unordered_set>

Json::Value get_all_clients(const std::string& query);
std::unordered_set<std::string> get_scope(const std::string& scope);
std::string get_scope(const std::unordered_set<std::string>& scope);

#endif