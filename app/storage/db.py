

import mysql.connector
from mysql.connector import errorcode
import config  

#DB parameters from config.py
db_config = {
    'user': config.DB_USER,
    'password': config.DB_PASSWORD,
    'host': config.DB_HOST,
    'database': config.DB_NAME
}

def get_db_connection(): #Function to get a DB connection
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password (check config.py)")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print(f"Database '{config.DB_NAME}' does not exist.")
        else:
            print(err)
        return None

def create_users_table():
    conn = get_db_connection()
    if not conn:
        print("Error:Failed to connect to DB, cannot create table.")
        return

    cursor = conn.cursor()
    table_query = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL,
        registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    try:
        cursor.execute(table_query)
        conn.commit()
        print("Users table checked/created successfully.")
    except mysql.connector.Error as err:
        print(f"Failed to create table: {err}")
    finally:
        cursor.close()
        conn.close()

def register_user(email, username, salt, pwd_hash): #Function to register a new user
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"

    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        return True, "User registered successfully"
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_DUP_ENTRY:
            return False, "Email or username already exists"
        return False, str(err)
    finally:
        cursor.close()
        conn.close()

def get_user(email): #Function to retrieve user details by email
    conn = get_db_connection()
    if not conn:
        return None, "Database connection failed"

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            return user, "User found"
        else:
            return None, "User not found"
    except mysql.connector.Error as err:
        return None, str(err)
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    print("Initializing database...")
    create_users_table()
    print("Database initialization complete.")