import sqlite3
from getpass import getpass as masked_input
import bcrypt
import hmac
import hashlib
import os
import dotenv
import uuid

################################################################################################
################################################################################################
dotenv.load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY").encode()
################################################################################################
################################################################################################

class DataBase():

    con = sqlite3.connect("users.db")
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username_lookup TEXT UNIQUE,
    username TEXT UNIQUE NOT NULL)
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
    user_id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(user_id))
    """)

    con.commit()

    @staticmethod
    def AccountCreationDB(userID, userLookUp, password, username):
        DataBase.cur.execute("""
        INSERT INTO users (user_id, username_lookup, username)
        VALUES (?, ?, ?)
        """, (userID, userLookUp, username))

        DataBase.cur.execute("""
        INSERT INTO credentials (user_id, password_hash)
        VALUES (?, ?)
        """, (userID, password))

        DataBase.con.commit()

    def get_password_hash(user_id):
        DataBase.cur.execute("SELECT password_hash FROM credentials WHERE user_id = ? ", (user_id,))
        result = DataBase.cur.fetchone()
        return result[0] if result else None
    
    def get_user_id(verified_userID):
        DataBase.cur.execute("SELECT user_id FROM users WHERE username_lookup = ?", (verified_userID,))
        result_userID = DataBase.cur.fetchone()
        return result_userID if result_userID else None

    def get_username(user_id):
        DataBase.cur.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
        username_result = DataBase.cur.fetchone()[0]
        return username_result if username_result else None

################################################################################################

class Encrypt():

    @staticmethod
    def DetailsEncrypt(userID, password, userLookUp, username):
        userLookUp = hmac.new(SECRET_KEY,userLookUp.lower().encode(),hashlib.sha256).hexdigest()
        password = bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()   


        DataBase.AccountCreationDB(userID, userLookUp, password, username)

################################################################################################

class Verification(): 

    @staticmethod
    def PasswordVerification(stored_hash, password):
        passwordValid = bcrypt.checkpw(password.encode(),stored_hash.encode())
        return passwordValid
 
    @staticmethod   
    def UsernameVerification(username_input):
        username_lookup = hmac.new(SECRET_KEY,username_input.lower().encode(),hashlib.sha256).hexdigest()
        return username_lookup


################################################################################################


class AccountCreation(): 
    def Register():   

        userID = str(uuid.uuid4())
        
        print("\n\n\n\nCreate Account") 
        userLookUp = input("username: ")
        username = userLookUp
        password = masked_input("Password: ")
        checkPassword = masked_input("Confirm Password: ")

        while password !=checkPassword:
            print("\nPasswords do not match. Please try again.\n")
            password = masked_input("\nPassword: ")
            checkPassword = masked_input("Confirm Password: ")
        else:
            Encrypt.DetailsEncrypt(userID, password, userLookUp, username)
            print("Account created successfully.\n\n\n")
            return AccountCreation.Login()

    def Login():
        print("Account Manager\n")
        username_input = input("Username: ")
        password = masked_input("Password: ")
        verified_userID = Verification.UsernameVerification(username_input)
        get_stored_userID = DataBase.get_user_id(verified_userID)
        if not get_stored_userID:
            print("\nUsername does not exist.\n")
            print("Do you wish to create an account?  Y/N\n ")
            creation = input("--->")
            if creation.lower() == "y":
                return AccountCreation.Register()
            else:
                App.Run()
        else:
            user_id = get_stored_userID[0]
            get_username = DataBase.get_username(user_id)
            stored_hash = DataBase.get_password_hash(user_id)
            passwordValid = Verification.PasswordVerification(stored_hash, password)
            if passwordValid:
                print("\nLogin successful.\n")
                MainMenu.Main(get_username)
            else:
                print("\nInvalid details.\n")
                return AccountCreation.Login()

################################################################################################


class MainMenu():
    def Main(get_username):
        print("\n\n\n\n\nWelcome back! "+get_username+"\n\n\n")


################################################################################################


class App():
    def Run():
        print("== Myster v1 ==\n")
        print("1. Login")
        print("2. Register")
        #print("3. Forgot Password (n/a)")
        appStart = input("---> ")

        if appStart == "1":
            AccountCreation.Login()
        if appStart == "2":
            AccountCreation.Register()


App.Run()