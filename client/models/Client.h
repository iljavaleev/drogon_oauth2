/**
 *
 *  Client.h
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#pragma once
#include <drogon/orm/Result.h>
#include <drogon/orm/Row.h>
#include <drogon/orm/Field.h>
#include <drogon/orm/SqlBinder.h>
#include <drogon/orm/Mapper.h>
#include <drogon/orm/BaseBuilder.h>
#ifdef __cpp_impl_coroutine
#include <drogon/orm/CoroMapper.h>
#endif
#include <trantor/utils/Date.h>
#include <trantor/utils/Logger.h>
#include <json/json.h>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <tuple>
#include <stdint.h>
#include <iostream>

namespace drogon
{
namespace orm
{
class DbClient;
using DbClientPtr = std::shared_ptr<DbClient>;
}
}
namespace drogon_model
{
namespace client
{
class ClientGrantType;
class ClientResponseType;
class ClientScope;
class RedirectUri;
class State;
class Token;

class Client
{
  public:
    struct Cols
    {
        static const std::string _client_id;
        static const std::string _client_secret;
        static const std::string _client_id_created_at;
        static const std::string _client_id_expires_at;
        static const std::string _client_name;
        static const std::string _client_uri;
        static const std::string _registration_client_uri;
        static const std::string _registration_access_token;
    };

    static const int primaryKeyNumber;
    static const std::string tableName;
    static const bool hasPrimaryKey;
    static const std::string primaryKeyName;
    using PrimaryKeyType = std::string;
    const PrimaryKeyType &getPrimaryKey() const;

    /**
     * @brief constructor
     * @param r One row of records in the SQL query result.
     * @param indexOffset Set the offset to -1 to access all columns by column names,
     * otherwise access all columns by offsets.
     * @note If the SQL is not a style of 'select * from table_name ...' (select all
     * columns by an asterisk), please set the offset to -1.
     */
    explicit Client(const drogon::orm::Row &r, const ssize_t indexOffset = 0) noexcept;

    /**
     * @brief constructor
     * @param pJson The json object to construct a new instance.
     */
    explicit Client(const Json::Value &pJson) noexcept(false);

    /**
     * @brief constructor
     * @param pJson The json object to construct a new instance.
     * @param pMasqueradingVector The aliases of table columns.
     */
    Client(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false);

    Client() = default;

    void updateByJson(const Json::Value &pJson) noexcept(false);
    void updateByMasqueradedJson(const Json::Value &pJson,
                                 const std::vector<std::string> &pMasqueradingVector) noexcept(false);
    static bool validateJsonForCreation(const Json::Value &pJson, std::string &err);
    static bool validateMasqueradedJsonForCreation(const Json::Value &,
                                                const std::vector<std::string> &pMasqueradingVector,
                                                    std::string &err);
    static bool validateJsonForUpdate(const Json::Value &pJson, std::string &err);
    static bool validateMasqueradedJsonForUpdate(const Json::Value &,
                                          const std::vector<std::string> &pMasqueradingVector,
                                          std::string &err);
    static bool validJsonOfField(size_t index,
                          const std::string &fieldName,
                          const Json::Value &pJson,
                          std::string &err,
                          bool isForCreation);

    /**  For column client_id  */
    ///Get the value of the column client_id, returns the default value if the column is null
    const std::string &getValueOfClientId() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getClientId() const noexcept;
    ///Set the value of the column client_id
    void setClientId(const std::string &pClientId) noexcept;
    void setClientId(std::string &&pClientId) noexcept;

    /**  For column client_secret  */
    ///Get the value of the column client_secret, returns the default value if the column is null
    const std::string &getValueOfClientSecret() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getClientSecret() const noexcept;
    ///Set the value of the column client_secret
    void setClientSecret(const std::string &pClientSecret) noexcept;
    void setClientSecret(std::string &&pClientSecret) noexcept;

    /**  For column client_id_created_at  */
    ///Get the value of the column client_id_created_at, returns the default value if the column is null
    const ::trantor::Date &getValueOfClientIdCreatedAt() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<::trantor::Date> &getClientIdCreatedAt() const noexcept;
    ///Set the value of the column client_id_created_at
    void setClientIdCreatedAt(const ::trantor::Date &pClientIdCreatedAt) noexcept;
    void setClientIdCreatedAtToNull() noexcept;

    /**  For column client_id_expires_at  */
    ///Get the value of the column client_id_expires_at, returns the default value if the column is null
    const ::trantor::Date &getValueOfClientIdExpiresAt() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<::trantor::Date> &getClientIdExpiresAt() const noexcept;
    ///Set the value of the column client_id_expires_at
    void setClientIdExpiresAt(const ::trantor::Date &pClientIdExpiresAt) noexcept;
    void setClientIdExpiresAtToNull() noexcept;

    /**  For column client_name  */
    ///Get the value of the column client_name, returns the default value if the column is null
    const std::string &getValueOfClientName() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getClientName() const noexcept;
    ///Set the value of the column client_name
    void setClientName(const std::string &pClientName) noexcept;
    void setClientName(std::string &&pClientName) noexcept;
    void setClientNameToNull() noexcept;

    /**  For column client_uri  */
    ///Get the value of the column client_uri, returns the default value if the column is null
    const std::string &getValueOfClientUri() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getClientUri() const noexcept;
    ///Set the value of the column client_uri
    void setClientUri(const std::string &pClientUri) noexcept;
    void setClientUri(std::string &&pClientUri) noexcept;
    void setClientUriToNull() noexcept;

    /**  For column registration_client_uri  */
    ///Get the value of the column registration_client_uri, returns the default value if the column is null
    const std::string &getValueOfRegistrationClientUri() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getRegistrationClientUri() const noexcept;
    ///Set the value of the column registration_client_uri
    void setRegistrationClientUri(const std::string &pRegistrationClientUri) noexcept;
    void setRegistrationClientUri(std::string &&pRegistrationClientUri) noexcept;
    void setRegistrationClientUriToNull() noexcept;

    /**  For column registration_access_token  */
    ///Get the value of the column registration_access_token, returns the default value if the column is null
    const std::string &getValueOfRegistrationAccessToken() const noexcept;
    ///Return a shared_ptr object pointing to the column const value, or an empty shared_ptr object if the column is null
    const std::shared_ptr<std::string> &getRegistrationAccessToken() const noexcept;
    ///Set the value of the column registration_access_token
    void setRegistrationAccessToken(const std::string &pRegistrationAccessToken) noexcept;
    void setRegistrationAccessToken(std::string &&pRegistrationAccessToken) noexcept;
    void setRegistrationAccessTokenToNull() noexcept;


    static size_t getColumnNumber() noexcept {  return 8;  }
    static const std::string &getColumnName(size_t index) noexcept(false);

    Json::Value toJson() const;
    Json::Value toMasqueradedJson(const std::vector<std::string> &pMasqueradingVector) const;
    /// Relationship interfaces
    std::vector<ClientGrantType> getGrantType(const drogon::orm::DbClientPtr &clientPtr) const;
    void getGrantType(const drogon::orm::DbClientPtr &clientPtr,
                      const std::function<void(std::vector<ClientGrantType>)> &rcb,
                      const drogon::orm::ExceptionCallback &ecb) const;
    std::vector<ClientResponseType> getResponseType(const drogon::orm::DbClientPtr &clientPtr) const;
    void getResponseType(const drogon::orm::DbClientPtr &clientPtr,
                         const std::function<void(std::vector<ClientResponseType>)> &rcb,
                         const drogon::orm::ExceptionCallback &ecb) const;
    std::vector<ClientScope> getScope(const drogon::orm::DbClientPtr &clientPtr) const;
    void getScope(const drogon::orm::DbClientPtr &clientPtr,
                  const std::function<void(std::vector<ClientScope>)> &rcb,
                  const drogon::orm::ExceptionCallback &ecb) const;
    std::vector<RedirectUri> getRedirectUri(const drogon::orm::DbClientPtr &clientPtr) const;
    void getRedirectUri(const drogon::orm::DbClientPtr &clientPtr,
                        const std::function<void(std::vector<RedirectUri>)> &rcb,
                        const drogon::orm::ExceptionCallback &ecb) const;
    Token getToken(const drogon::orm::DbClientPtr &clientPtr) const;
    void getToken(const drogon::orm::DbClientPtr &clientPtr,
                  const std::function<void(Token)> &rcb,
                  const drogon::orm::ExceptionCallback &ecb) const;
    State getState(const drogon::orm::DbClientPtr &clientPtr) const;
    void getState(const drogon::orm::DbClientPtr &clientPtr,
                  const std::function<void(State)> &rcb,
                  const drogon::orm::ExceptionCallback &ecb) const;
  private:
    friend drogon::orm::Mapper<Client>;
    friend drogon::orm::BaseBuilder<Client, true, true>;
    friend drogon::orm::BaseBuilder<Client, true, false>;
    friend drogon::orm::BaseBuilder<Client, false, true>;
    friend drogon::orm::BaseBuilder<Client, false, false>;
#ifdef __cpp_impl_coroutine
    friend drogon::orm::CoroMapper<Client>;
#endif
    static const std::vector<std::string> &insertColumns() noexcept;
    void outputArgs(drogon::orm::internal::SqlBinder &binder) const;
    const std::vector<std::string> updateColumns() const;
    void updateArgs(drogon::orm::internal::SqlBinder &binder) const;
    ///For mysql or sqlite3
    void updateId(const uint64_t id);
    std::shared_ptr<std::string> clientId_;
    std::shared_ptr<std::string> clientSecret_;
    std::shared_ptr<::trantor::Date> clientIdCreatedAt_;
    std::shared_ptr<::trantor::Date> clientIdExpiresAt_;
    std::shared_ptr<std::string> clientName_;
    std::shared_ptr<std::string> clientUri_;
    std::shared_ptr<std::string> registrationClientUri_;
    std::shared_ptr<std::string> registrationAccessToken_;
    struct MetaData
    {
        const std::string colName_;
        const std::string colType_;
        const std::string colDatabaseType_;
        const ssize_t colLength_;
        const bool isAutoVal_;
        const bool isPrimaryKey_;
        const bool notNull_;
    };
    static const std::vector<MetaData> metaData_;
    bool dirtyFlag_[8]={ false };
  public:
    static const std::string &sqlForFindingByPrimaryKey()
    {
        static const std::string sql="select * from " + tableName + " where client_id = $1";
        return sql;
    }

    static const std::string &sqlForDeletingByPrimaryKey()
    {
        static const std::string sql="delete from " + tableName + " where client_id = $1";
        return sql;
    }
    std::string sqlForInserting(bool &needSelection) const
    {
        std::string sql="insert into " + tableName + " (";
        size_t parametersCount = 0;
        needSelection = false;
        if(dirtyFlag_[0])
        {
            sql += "client_id,";
            ++parametersCount;
        }
        if(dirtyFlag_[1])
        {
            sql += "client_secret,";
            ++parametersCount;
        }
        if(dirtyFlag_[2])
        {
            sql += "client_id_created_at,";
            ++parametersCount;
        }
        if(dirtyFlag_[3])
        {
            sql += "client_id_expires_at,";
            ++parametersCount;
        }
        if(dirtyFlag_[4])
        {
            sql += "client_name,";
            ++parametersCount;
        }
        if(dirtyFlag_[5])
        {
            sql += "client_uri,";
            ++parametersCount;
        }
        if(dirtyFlag_[6])
        {
            sql += "registration_client_uri,";
            ++parametersCount;
        }
        if(dirtyFlag_[7])
        {
            sql += "registration_access_token,";
            ++parametersCount;
        }
        if(parametersCount > 0)
        {
            sql[sql.length()-1]=')';
            sql += " values (";
        }
        else
            sql += ") values (";

        int placeholder=1;
        char placeholderStr[64];
        size_t n=0;
        if(dirtyFlag_[0])
        {
            n = snprintf(placeholderStr,sizeof(placeholderStr),"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[1])
        {
            n = snprintf(placeholderStr,sizeof(placeholderStr),"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[2])
        {
            n = snprintf(placeholderStr,sizeof(placeholderStr),"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[3])
        {
            n = snprintf(placeholderStr,sizeof(placeholderStr),"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[4])
        {
            n = snprintf(placeholderStr,sizeof(placeholderStr),"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[5])
        {
            n = snprintf(placeholderStr,sizeof(placeholderStr),"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[6])
        {
            n = snprintf(placeholderStr,sizeof(placeholderStr),"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(dirtyFlag_[7])
        {
            n = snprintf(placeholderStr,sizeof(placeholderStr),"$%d,",placeholder++);
            sql.append(placeholderStr, n);
        }
        if(parametersCount > 0)
        {
            sql.resize(sql.length() - 1);
        }
        if(needSelection)
        {
            sql.append(") returning *");
        }
        else
        {
            sql.append(1, ')');
        }
        LOG_TRACE << sql;
        return sql;
    }
};
} // namespace client
} // namespace drogon_model
