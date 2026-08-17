import snowflake.connector
import json
import getpass
import sys
from datetime import datetime
from snowflake.connector.errors import Error as SnowflakeError

# Define connection constants



def get_snowflake_connection(username, password, account, authenticator, warehouse, database, schema, role):
    try:
        # Connect to Snowflake using provided credentials and parameters
        conn = snowflake.connector.connect(
            user=username,
            password=password,
            account=account,
            authenticator=authenticator,
            warehouse=warehouse,
            schema=schema,
            role=role,
            database=database
        )
        print(f"Connected to Snowflake Database: username: {username}, account: {account}, warehouse: {warehouse}, role: {role}, schema: {schema}, database: {database}") 
        return conn

    except SnowflakeError as error:
        print(f"Failed to connect to Snowflake: {error}")
        return None

# Example usage

WAREHOUSE = "test"
DATABASE = "test"
SCHEMA = "test"
ROLE = "test"
connection1 = get_snowflake_connection(USERNAME, PASSWORD, ACCOUNT, AUTHENTICATOR, WAREHOUSE, DATABASE, SCHEMA, ROLE)

if connection1:
    print("Connected to Connection1")
    connection1.close()

WAREHOUSE2 = "test"
DATABASE2 = "test"
SCHEMA2= "test"
ROLE2 = "test"  # Removed the semicolon here
connection2 = get_snowflake_connection(USERNAME, PASSWORD, ACCOUNT, AUTHENTICATOR, WAREHOUSE2, DATABASE2, SCHEMA2, ROLE2)

if connection2:
    print("Connected to Connection2")
    connection2.close()
