/**
 *
 *  Request.cc
 *  DO NOT EDIT. This file is generated by drogon_ctl
 *
 */

#include "Request.h"
#include <drogon/utils/Utilities.h>
#include <string>

using namespace drogon;
using namespace drogon::orm;
using namespace drogon_model::auth_server;

const std::string Request::Cols::_request_id = "\"request_id\"";
const std::string Request::Cols::_query = "\"query\"";
const std::string Request::primaryKeyName = "request_id";
const bool Request::hasPrimaryKey = true;
const std::string Request::tableName = "\"request\"";

const std::vector<typename Request::MetaData> Request::metaData_={
{"request_id","std::string","character varying",128,0,1,1},
{"query","std::string","text",0,0,0,0}
};
const std::string &Request::getColumnName(size_t index) noexcept(false)
{
    assert(index < metaData_.size());
    return metaData_[index].colName_;
}
Request::Request(const Row &r, const ssize_t indexOffset) noexcept
{
    if(indexOffset < 0)
    {
        if(!r["request_id"].isNull())
        {
            requestId_=std::make_shared<std::string>(r["request_id"].as<std::string>());
        }
        if(!r["query"].isNull())
        {
            query_=std::make_shared<std::string>(r["query"].as<std::string>());
        }
    }
    else
    {
        size_t offset = (size_t)indexOffset;
        if(offset + 2 > r.size())
        {
            LOG_FATAL << "Invalid SQL result for this model";
            return;
        }
        size_t index;
        index = offset + 0;
        if(!r[index].isNull())
        {
            requestId_=std::make_shared<std::string>(r[index].as<std::string>());
        }
        index = offset + 1;
        if(!r[index].isNull())
        {
            query_=std::make_shared<std::string>(r[index].as<std::string>());
        }
    }

}

Request::Request(const Json::Value &pJson, const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 2)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        dirtyFlag_[0] = true;
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            requestId_=std::make_shared<std::string>(pJson[pMasqueradingVector[0]].asString());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            query_=std::make_shared<std::string>(pJson[pMasqueradingVector[1]].asString());
        }
    }
}

Request::Request(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("request_id"))
    {
        dirtyFlag_[0]=true;
        if(!pJson["request_id"].isNull())
        {
            requestId_=std::make_shared<std::string>(pJson["request_id"].asString());
        }
    }
    if(pJson.isMember("query"))
    {
        dirtyFlag_[1]=true;
        if(!pJson["query"].isNull())
        {
            query_=std::make_shared<std::string>(pJson["query"].asString());
        }
    }
}

void Request::updateByMasqueradedJson(const Json::Value &pJson,
                                            const std::vector<std::string> &pMasqueradingVector) noexcept(false)
{
    if(pMasqueradingVector.size() != 2)
    {
        LOG_ERROR << "Bad masquerading vector";
        return;
    }
    if(!pMasqueradingVector[0].empty() && pJson.isMember(pMasqueradingVector[0]))
    {
        if(!pJson[pMasqueradingVector[0]].isNull())
        {
            requestId_=std::make_shared<std::string>(pJson[pMasqueradingVector[0]].asString());
        }
    }
    if(!pMasqueradingVector[1].empty() && pJson.isMember(pMasqueradingVector[1]))
    {
        dirtyFlag_[1] = true;
        if(!pJson[pMasqueradingVector[1]].isNull())
        {
            query_=std::make_shared<std::string>(pJson[pMasqueradingVector[1]].asString());
        }
    }
}

void Request::updateByJson(const Json::Value &pJson) noexcept(false)
{
    if(pJson.isMember("request_id"))
    {
        if(!pJson["request_id"].isNull())
        {
            requestId_=std::make_shared<std::string>(pJson["request_id"].asString());
        }
    }
    if(pJson.isMember("query"))
    {
        dirtyFlag_[1] = true;
        if(!pJson["query"].isNull())
        {
            query_=std::make_shared<std::string>(pJson["query"].asString());
        }
    }
}

const std::string &Request::getValueOfRequestId() const noexcept
{
    static const std::string defaultValue = std::string();
    if(requestId_)
        return *requestId_;
    return defaultValue;
}
const std::shared_ptr<std::string> &Request::getRequestId() const noexcept
{
    return requestId_;
}
void Request::setRequestId(const std::string &pRequestId) noexcept
{
    requestId_ = std::make_shared<std::string>(pRequestId);
    dirtyFlag_[0] = true;
}
void Request::setRequestId(std::string &&pRequestId) noexcept
{
    requestId_ = std::make_shared<std::string>(std::move(pRequestId));
    dirtyFlag_[0] = true;
}
const typename Request::PrimaryKeyType & Request::getPrimaryKey() const
{
    assert(requestId_);
    return *requestId_;
}

const std::string &Request::getValueOfQuery() const noexcept
{
    static const std::string defaultValue = std::string();
    if(query_)
        return *query_;
    return defaultValue;
}
const std::shared_ptr<std::string> &Request::getQuery() const noexcept
{
    return query_;
}
void Request::setQuery(const std::string &pQuery) noexcept
{
    query_ = std::make_shared<std::string>(pQuery);
    dirtyFlag_[1] = true;
}
void Request::setQuery(std::string &&pQuery) noexcept
{
    query_ = std::make_shared<std::string>(std::move(pQuery));
    dirtyFlag_[1] = true;
}
void Request::setQueryToNull() noexcept
{
    query_.reset();
    dirtyFlag_[1] = true;
}

void Request::updateId(const uint64_t id)
{
}

const std::vector<std::string> &Request::insertColumns() noexcept
{
    static const std::vector<std::string> inCols={
        "request_id",
        "query"
    };
    return inCols;
}

void Request::outputArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[0])
    {
        if(getRequestId())
        {
            binder << getValueOfRequestId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[1])
    {
        if(getQuery())
        {
            binder << getValueOfQuery();
        }
        else
        {
            binder << nullptr;
        }
    }
}

const std::vector<std::string> Request::updateColumns() const
{
    std::vector<std::string> ret;
    if(dirtyFlag_[0])
    {
        ret.push_back(getColumnName(0));
    }
    if(dirtyFlag_[1])
    {
        ret.push_back(getColumnName(1));
    }
    return ret;
}

void Request::updateArgs(drogon::orm::internal::SqlBinder &binder) const
{
    if(dirtyFlag_[0])
    {
        if(getRequestId())
        {
            binder << getValueOfRequestId();
        }
        else
        {
            binder << nullptr;
        }
    }
    if(dirtyFlag_[1])
    {
        if(getQuery())
        {
            binder << getValueOfQuery();
        }
        else
        {
            binder << nullptr;
        }
    }
}
Json::Value Request::toJson() const
{
    Json::Value ret;
    if(getRequestId())
    {
        ret["request_id"]=getValueOfRequestId();
    }
    else
    {
        ret["request_id"]=Json::Value();
    }
    if(getQuery())
    {
        ret["query"]=getValueOfQuery();
    }
    else
    {
        ret["query"]=Json::Value();
    }
    return ret;
}

Json::Value Request::toMasqueradedJson(
    const std::vector<std::string> &pMasqueradingVector) const
{
    Json::Value ret;
    if(pMasqueradingVector.size() == 2)
    {
        if(!pMasqueradingVector[0].empty())
        {
            if(getRequestId())
            {
                ret[pMasqueradingVector[0]]=getValueOfRequestId();
            }
            else
            {
                ret[pMasqueradingVector[0]]=Json::Value();
            }
        }
        if(!pMasqueradingVector[1].empty())
        {
            if(getQuery())
            {
                ret[pMasqueradingVector[1]]=getValueOfQuery();
            }
            else
            {
                ret[pMasqueradingVector[1]]=Json::Value();
            }
        }
        return ret;
    }
    LOG_ERROR << "Masquerade failed";
    if(getRequestId())
    {
        ret["request_id"]=getValueOfRequestId();
    }
    else
    {
        ret["request_id"]=Json::Value();
    }
    if(getQuery())
    {
        ret["query"]=getValueOfQuery();
    }
    else
    {
        ret["query"]=Json::Value();
    }
    return ret;
}

bool Request::validateJsonForCreation(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("request_id"))
    {
        if(!validJsonOfField(0, "request_id", pJson["request_id"], err, true))
            return false;
    }
    else
    {
        err="The request_id column cannot be null";
        return false;
    }
    if(pJson.isMember("query"))
    {
        if(!validJsonOfField(1, "query", pJson["query"], err, true))
            return false;
    }
    return true;
}
bool Request::validateMasqueradedJsonForCreation(const Json::Value &pJson,
                                                 const std::vector<std::string> &pMasqueradingVector,
                                                 std::string &err)
{
    if(pMasqueradingVector.size() != 2)
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
        else
        {
            err="The " + pMasqueradingVector[0] + " column cannot be null";
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
    }
    catch(const Json::LogicError &e)
    {
      err = e.what();
      return false;
    }
    return true;
}
bool Request::validateJsonForUpdate(const Json::Value &pJson, std::string &err)
{
    if(pJson.isMember("request_id"))
    {
        if(!validJsonOfField(0, "request_id", pJson["request_id"], err, false))
            return false;
    }
    else
    {
        err = "The value of primary key must be set in the json object for update";
        return false;
    }
    if(pJson.isMember("query"))
    {
        if(!validJsonOfField(1, "query", pJson["query"], err, false))
            return false;
    }
    return true;
}
bool Request::validateMasqueradedJsonForUpdate(const Json::Value &pJson,
                                               const std::vector<std::string> &pMasqueradingVector,
                                               std::string &err)
{
    if(pMasqueradingVector.size() != 2)
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
    }
    catch(const Json::LogicError &e)
    {
      err = e.what();
      return false;
    }
    return true;
}
bool Request::validJsonOfField(size_t index,
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
            break;
        default:
            err="Internal error in the server";
            return false;
    }
    return true;
}
