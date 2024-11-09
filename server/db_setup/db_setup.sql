DROP TABLE IF EXISTS client cascade;
DROP TABLE IF EXISTS token;
DROP TABLE IF EXISTS protected_resource;
DROP TABLE IF EXISTS request;
DROP TABLE IF EXISTS code;
DROP TABLE IF EXISTS client_grant_type;
DROP TABLE IF EXISTS client_response_type;
DROP TABLE IF EXISTS client_scope;
DROP TABLE IF EXISTS redirect_uri;
DROP TYPE IF EXISTS grant_type;
DROP TYPE IF EXISTS response_type;
DROP TYPE IF EXISTS scope;

CREATE TYPE grant_type AS ENUM ('authorization_code', 'refresh_token');
CREATE TYPE response_type AS ENUM ('code', 'token', 'id_token');
CREATE TYPE scope AS ENUM ('foo', 'bar', 'gin', 'juice');


CREATE TABLE client(
    client_id varchar(128) PRIMARY KEY,
    client_secret varchar(128) NOT NULL,
    client_id_created_at date,
    client_id_expires_at date,
    client_name varchar(128),
    client_uri varchar(128),
    registration_client_uri text,
    registration_access_token text
);

CREATE TABLE client_grant_type(
    client_id varchar(128),
    grant_type grant_type,
    FOREIGN KEY (client_id) REFERENCES client (client_id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, grant_type) 
);

CREATE TABLE client_response_type(
    client_id varchar(128),
    response_type response_type,
    FOREIGN KEY (client_id) REFERENCES client (client_id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, response_type) 
);

CREATE TABLE client_scope(
    client_id varchar(128),
    scope scope,
    FOREIGN KEY (client_id) REFERENCES client (client_id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE redirect_uri(
    id SERIAL PRIMARY KEY,
    client_id varchar(128),
    uri text,
    FOREIGN KEY (client_id) REFERENCES client (client_id) ON DELETE CASCADE
);

-- refresh table
CREATE TABLE token(
    id SERIAL PRIMARY KEY,
    client_id varchar(128),
    access_token text,
    refresh_token text,
    access_token_expire text,
    scope varchar(255),
    UNIQUE (id, client_id),
    FOREIGN KEY (client_id) REFERENCES client (client_id) ON DELETE CASCADE
);

CREATE TABLE protected_resource(
    resource_id varchar(128) PRIMARY KEY,
    resource_uri text
);

CREATE TABLE request(
    request_id varchar(128) PRIMARY KEY,
    query text
);

CREATE TABLE code(
    code varchar(64) PRIMARY KEY,
    query text,
    scope scope[]
);
