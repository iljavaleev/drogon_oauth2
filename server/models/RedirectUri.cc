/**
 *
 *  RedirectUri.cc
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#include "RedirectUri.h"
#include "Client.h"
#include <drogon/utils/Utilities.h>
#include <string>

using namespace drogon;
using namespace drogon::orm;
using namespace drogon_model::auth_server;

const std::string RedirectUri::Cols::_id = "\"id\"";
const std::string RedirectUri::Cols::_client_id = "\"client_id\"";
const std::string RedirectUri::Cols::_uri = "\"uri\"";
const std::string RedirectUri::primaryKeyName = "id";
const bool RedirectUri::hasPrimaryKey = true;
const std::string RedirectUri::tableName = "\"redirect_uri\"";

const std::vector<typename RedirectUri::MetaData> RedirectUri::metaData_={
{"id","int32_t","integer",4,1,1,1},
{"client_id","std::string","character varying",128,0,0,0},
{"uri","std::string","text",0,0,0,0}
};
const std::string &RedirectUri::getColumnName(size_t index) noexcept(false)
{
    assert(index < metaData_.size());
    return metaData_[index].colName_;
}
RedirectUri::RedirectUri(const Row &r, const ssize_t indexOffset) noexcept
{
    if(indexOffset < 0)
    {
        if(!r["id"].isNull())
        {
            id_=std::make_shared<int32_t>(r["id"].as<int32_t>());
        }
        if(!r["client_id"].isNull())
        {
            clientId_=std::make_shared<std::string>(r["client_id"].as<std::string>());
        }
        if(!r["uri"].isNull())
        {
            uri_=std::make_shared<std::string>(r["uri"].as<std::string>());
        }
    }
    else
    {
        size_t offset = (size_t)indexOffset;
        if(offset + 3 > r.size())
        {
            LOG_FATAL << "Invalid SQL result for this model";
            return;
        }
        size_t index;
        index = offset + 0;
        if(!r[index].isNull())
        {
            id_=std::make_shared<int32_t>(r[index].as<int32_t>());
        }
        index = offset + 1;
        if(!r[index].isNull())
        {
            clientId_=std::make_shared<std::string>(r[index].as<std::string>());
        }
        index = offset + 2;
        if(!r[index].isNull())
        {
            uri_=std::make_shared<std::string>(r[index].as<std::string>());
        }
    }

}

RedirectUri::RedirectUri(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 3)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        dirtyFlag_[0] = true;
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            id_=std::make_shared<int32_t>((int32_t)pJson[pMasqueradingVector[0]].asInt64());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            clientId_=std::make_shared<std::string>(pJson[pMasqueradingVector[1]].asString());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            uri_=std::make_shared<std::string>(pJson[pMasqueradingVector[2]].asString());
        }
    }
}

RedirectUri::RedirectUri(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("id"))
    {
        dirtyFlag_[0]=true;
        if(!pJson["id"].isNull())
        {
            id_=std::make_shared<int32_t>((int32_t)pJson["id"].asInt64());
        }
    }
    if(pJson.isMember("client_id"))
    {
        dirtyFlag_[1]=true;
        if(!pJson["client_id"].isNull())
        {
            clientId_=std::make_shared<std::string>(pJson["client_id"].asString());
        }
    }
    if(pJson.isMember("uri"))
    {
        dirtyFlag_[2]=true;
        if(!pJson["uri"].isNull())
        {
            uri_=std::make_shared<std::string>(pJson["uri"].asString());
        }
    }
}

void RedirectUri::updateByMasqueradedJson(const Json::Value &pJson,
                                            const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 3)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            id_=std::make_shared<int32_t>((int32_t)pJson[pMasqueradingVector[0]].asInt64());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            clientId_=std::make_shared<std::string>(pJson[pMasqueradingVector[1]].asString());
        }
    }
    if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
    {
        dirtyFlag_[2] = true;
        if(!pJson[pMasqueradingVector[2]].isNull())
        {
            uri_=std::make_shared<std::string>(pJson[pMasqueradingVector[2]].asString());
        }
    }
}

void RedirectUri::updateByJson(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("id"))
    {
        if(!pJson["id"].isNull())
        {
            id_=std::make_shared<int32_t>((int32_t)pJson["id"].asInt64());
        }
    }
    if(pJson.isMember("client_id"))
    {
        dirtyFlag_[1] = true;
        if(!pJson["client_id"].isNull())
        {
            clientId_=std::make_shared<std::string>(pJson["client_id"].asString());
        }
    }
    if(pJson.isMember("uri"))
    {
        dirtyFlag_[2] = true;
        if(!pJson["uri"].isNull())
        {
            uri_=std::make_shared<std::string>(pJson["uri"].asString());
        }
    }
}

const int32_t &RedirectUri::getValueOfId() const noexcept
{
    static const int32_t defaultValue = int32_t();
    if(id_)
        return *id_;
    return defaultValue;
}
const std::shared_ptr<int32_t> &RedirectUri::getId() const noexcept
{
    return id_;
}
void RedirectUri::setId(const int32_t &pId) noexcept
{
    id_ = std::make_shared<int32_t>(pId);
    dirtyFlag_[0] = true;
}
const typename RedirectUri::PrimaryKeyType & RedirectUri::getPrimaryKey() const
{
    assert(id_);
    return *id_;
}

const std::string &RedirectUri::getValueOfClientId() const noexcept
{
    static const std::string defaultValue = std::string();
    if(clientId_)
        return *clientId_;
    return defaultValue;
}
const std::shared_ptr<std::string> &RedirectUri::getClientId() const noexcept
{
    return clientId_;
}
void RedirectUri::setClientId(const std::string &pClientId) noexcept
{
    clientId_ = std::make_shared<std::string>(pClientId);
    dirtyFlag_[1] = true;
}
void RedirectUri::setClientId(std::string &&pClientId) noexcept
{
    clientId_ = std::make_shared<std::string>(std::move(pClientId));
    dirtyFlag_[1] = true;
}
void RedirectUri::setClientIdToNull() noexcept
{
    clientId_.reset();
    dirtyFlag_[1] = true;
}

const std::string &RedirectUri::getValueOfUri() const noexcept
{
    static const std::string defaultValue = std::string();
    if(uri_)
        return *uri_;
    return defaultValue;
}
const std::shared_ptr<std::string> &RedirectUri::getUri() const noexcept
{
    return uri_;
}
void RedirectUri::setUri(const std::string &pUri) noexcept
{
    uri_ = std::make_shared<std::string>(pUri);
    dirtyFlag_[2] = true;
}
void RedirectUri::setUri(std::string &&pUri) noexcept
{
    uri_ = std::make_shared<std::string>(std::move(pUri));
    dirtyFlag_[2] = true;
}
void RedirectUri::setUriToNull() noexcept
{
    uri_.reset();
    dirtyFlag_[2] = true;
}

void RedirectUri::updateId(const uint64_t id)
{
}

const std::vector<std::string> &RedirectUri::insertColumns() noexcept
{
    static const std::vector<std::string> inCols={
        "client_id",
        "uri"
    };
    return inCols;
}

void RedirectUri::outputArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getClientId())
        {
            binder << getValueOfClientId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getUri())
        {
            binder << getValueOfUri();
        }
        else
        {
            binder << nullptr;
        }
    }
}

const std::vector<std::string> RedirectUri::updateColumns() const
{
    std::vector<std::string> ret;
    if(dirtyFlag_[1])
    {
        ret.push_back(getColumnName(1));
    }
    if(dirtyFlag_[2])
    {
        ret.push_back(getColumnName(2));
    }
    return ret;
}

void RedirectUri::updateArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[1])
    {
        if(getClientId())
        {
            binder << getValueOfClientId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[2])
    {
        if(getUri())
        {
            binder << getValueOfUri();
        }
        else
        {
            binder << nullptr;
        }
    }
}
Json::Value RedirectUri::toJson() const
{
    Json::Value ret;
    if(getId())
    {
        ret["id"]=getValueOfId();
    }
    else
    {
        ret["id"]=Json::Value();
    }
    if(getClientId())
    {
        ret["client_id"]=getValueOfClientId();
    }
    else
    {
        ret["client_id"]=Json::Value();
    }
    if(getUri())
    {
        ret["uri"]=getValueOfUri();
    }
    else
    {
        ret["uri"]=Json::Value();
    }
    return ret;
}

Json::Value RedirectUri::toMasqueradedJson(
    const std::vector<std::string> &pMasqueradingVector) const
{
    Json::Value ret;
    if(pMasqueradingVector.size() == 3)
    {
        if(!pMasqueradingVector[0].empty())
        {
            if(getId())
            {
                ret[pMasqueradingVector[0]]=getValueOfId();
            }
            else
            {
                ret[pMasqueradingVector[0]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[1].empty())
        {
            if(getClientId())
            {
                ret[pMasqueradingVector[1]]=getValueOfClientId();
            }
            else
            {
                ret[pMasqueradingVector[1]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[2].empty())
        {
            if(getUri())
            {
                ret[pMasqueradingVector[2]]=getValueOfUri();
            }
            else
            {
                ret[pMasqueradingVector[2]]=Json::Value();
            }
        }
        return ret;
    }
    LOG_ERROR << "Masquerade failed";
    if(getId())
    {
        ret["id"]=getValueOfId();
    }
    else
    {
        ret["id"]=Json::Value();
    }
    if(getClientId())
    {
        ret["client_id"]=getValueOfClientId();
    }
    else
    {
        ret["client_id"]=Json::Value();
    }
    if(getUri())
    {
        ret["uri"]=getValueOfUri();
    }
    else
    {
        ret["uri"]=Json::Value();
    }
    return ret;
}

bool RedirectUri::validateJsonForCreation(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("id"))
    {
        if(!validJsonOfField(0, "id", pJson["id"], err, true))
            return false;
    }
    if(pJson.isMember("client_id"))
    {
        if(!validJsonOfField(1, "client_id", pJson["client_id"], err, true))
            return false;
    }
    if(pJson.isMember("uri"))
    {
        if(!validJsonOfField(2, "uri", pJson["uri"], err, true))
            return false;
    }
    return true;
}
bool RedirectUri::validateMasqueradedJsonForCreation(const Json::Value &pJson,
                                                     const std::vector<std::string> &pMasqueradingVector,
                                                     std::string &err)
{
    if(pMasqueradingVector.size() != 3)
    {
        err = "Bad masquerading vector";
        return false;
    }
    try {
      if(!pMasqueradingVector[0].empty())
      {
          if(pJson.isMember(pMasqueradingVector[0]))
          {
              if(!validJsonOfField(0, pMasqueradingVector[0], pJson[pMasqueradingVector[0]], err, true))
                  return false;
          }
      }
      if(!pMasqueradingVector[1].empty())
      {
          if(pJson.isMember(pMasqueradingVector[1]))
          {
              if(!validJsonOfField(1, pMasqueradingVector[1], pJson[pMasqueradingVector[1]], err, true))
                  return false;
          }
      }
      if(!pMasqueradingVector[2].empty())
      {
          if(pJson.isMember(pMasqueradingVector[2]))
          {
              if(!validJsonOfField(2, pMasqueradingVector[2], pJson[pMasqueradingVector[2]], err, true))
                  return false;
          }
      }
    }
    catch(const Json::LogicError &e)
    {
      err = e.what();
      return false;
    }
    return true;
}
bool RedirectUri::validateJsonForUpdate(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("id"))
    {
        if(!validJsonOfField(0, "id", pJson["id"], err, false))
            return false;
    }
    else
    {
        err = "The value of primary key must be set in the json object for update";
        return false;
    }
    if(pJson.isMember("client_id"))
    {
        if(!validJsonOfField(1, "client_id", pJson["client_id"], err, false))
            return false;
    }
    if(pJson.isMember("uri"))
    {
        if(!validJsonOfField(2, "uri", pJson["uri"], err, false))
            return false;
    }
    return true;
}
bool RedirectUri::validateMasqueradedJsonForUpdate(const Json::Value &pJson,
                                                   const std::vector<std::string> &pMasqueradingVector,
                                                   std::string &err)
{
    if(pMasqueradingVector.size() != 3)
    {
        err = "Bad masquerading vector";
        return false;
    }
    try {
      if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
      {
          if(!validJsonOfField(0, pMasqueradingVector[0], pJson[pMasqueradingVector[0]], err, false))
              return false;
      }
    else
    {
        err = "The value of primary key must be set in the json object for update";
        return false;
    }
      if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
      {
          if(!validJsonOfField(1, pMasqueradingVector[1], pJson[pMasqueradingVector[1]], err, false))
              return false;
      }
      if(!pMasqueradingVector[2].empty() && pJson.isMember(pMasqueradingVector[2]))
      {
          if(!validJsonOfField(2, pMasqueradingVector[2], pJson[pMasqueradingVector[2]], err, false))
              return false;
      }
    }
    catch(const Json::LogicError &e)
    {
      err = e.what();
      return false;
    }
    return true;
}
bool RedirectUri::validJsonOfField(size_t index,
                                   const std::string &fieldName,
                                   const Json::Value &pJson,
                                   std::string &err,
                                   bool isForCreation)
{
    switch(index)
    {
        case 0:
            if(pJson.isNull())
            {
                err="The " + fieldName + " column cannot be null";
                return false;
            }
            if(isForCreation)
            {
                err="The automatic primary key cannot be set";
                return false;
            }
            if(!pJson.isInt())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        case 1:
            if(pJson.isNull())
            {
                return true;
            }
            if(!pJson.isString())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            if(pJson.isString() && std::strlen(pJson.asCString()) > 128)
            {
                err="String length exceeds limit for the " +
                    fieldName +
                    " field (the maximum value is 128)";
                return false;
            }

            break;
        case 2:
            if(pJson.isNull())
            {
                return true;
            }
            if(!pJson.isString())
            {
                err="Type error in the "+fieldName+" field";
                return false;
            }
            break;
        default:
            err="Internal error in the server";
            return false;
    }
    return true;
}
Client RedirectUri::getClient(const DbClientPtr &clientPtr) const {
    static const std::string sql = "select * from client where client_id = $1";
    Result r(nullptr);
    {
        auto binder = *clientPtr << sql;
        binder << *clientId_ << Mode::Blocking >>
            [&r](const Result &result) { r = result; };
        binder.exec();
    }
    if (r.size() == 0)
    {
        throw UnexpectedRows("0 rows found");
    }
    else if (r.size() > 1)
    {
        throw UnexpectedRows("Found more than one row");
    }
    return Client(r[0]);
}

void RedirectUri::getClient(const DbClientPtr &clientPtr,
                            const std::function<void(Client)> &rcb,
                            const ExceptionCallback &ecb) const
{
    static const std::string sql = "select * from client where client_id = $1";
    *clientPtr << sql
               << *clientId_
               >> [rcb = std::move(rcb), ecb](const Result &r){
                    if (r.size() == 0)
                    {
                        ecb(UnexpectedRows("0 rows found"));
                    }
                    else if (r.size() > 1)
                    {
                        ecb(UnexpectedRows("Found more than one row"));
                    }
                    else
                    {
                        rcb(Client(r[0]));
                    }
               }
               >> ecb;
}
