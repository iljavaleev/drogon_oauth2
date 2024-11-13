#!/bin/bash
psql -U postgres -tc "SELECT 1 FROM pg_database WHERE datname = '${CLIENT_DB}'" | grep -q 1 || psql -U  ${POSTGRES_USER}  -c "CREATE DATABASE ${CLIENT_DB}"
psql -U postgres -d ${CLIENT_DB} -a -f ./db_setup.sql

export CLIENT_DB=client
export POSTGRES_USER=postgres
export WORKDIR=..

"http://localhost:9001/authorize", "http://localhost:9001/token"