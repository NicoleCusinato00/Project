import sqlite3
import hashlib
import argparse


# example of a simple password database with Python and SQLite.
#  - Prepared statements to avoid vulnerable SQL injection
#  - hashed passwords


# add a username
# python bad_password_db.py -a pippo -p pippopwd

# check if it exists and its balance
# python bad_password_db.py -c pippo -p pippopwd
# python bad_password_db.py -c pippo -p differentpwd  # will not work!


conn = None
cursor = None


def open_and_create():
    global conn
    global cursor
    conn = sqlite3.connect('example-pwd.db')
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM user")
    except sqlite3.OperationalError:
        # Create user and wallet table
        cursor.execute('''CREATE TABLE user
                     (username TEXT, password TEXT,
                      PRIMARY KEY (username))''')
        cursor.execute('''CREATE TABLE wallet
                     (username TEXT, balance INTEGER,
                      PRIMARY KEY (username),
                      FOREIGN KEY (username)
                        REFERENCES user(username))''')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', help="add a usernamename (requires -p)",
                        required=False)
    parser.add_argument('-p', help="the username password",
                        required=True)
    parser.add_argument('-c', help="check for a usernamename and password and return balance"
                                   "(requires -p)", required=False)
    parser.add_argument('-l', help="list all users", action='store_true',
                        required=False)
    return parser.parse_args()


def save_new_username_correct(username, password):
    global conn
    global cursor

    # compute hash of the password and store it in db
    digest = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # prepared statements to avoid sql injection
    cursor.execute("INSERT OR REPLACE INTO user VALUES (?,?)",
                   (username, digest))
    cursor.execute("INSERT OR REPLACE INTO wallet VALUES (?,?)",
                   (username, 10))
    conn.commit()


def check_for_username_correct(username, password):
    global conn
    global cursor

    # compute hash of password to check it
    digest = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # prepared statement
    rows = cursor.execute("SELECT * FROM user WHERE username=? and password=?",
                          (username, digest))
    conn.commit()
    results = rows.fetchall()
    # NOTE: this could be done more efficiently with a JOIN
    if results:
        b = cursor.execute("SELECT balance FROM wallet WHERE username=?",
                           (results[0][0],))
        print("User is present, password is valid, balance is %s"
              % b.fetchall()[0][0])
    else:
        print("User is not present, or password is invalid")


def print_all_users():
    rows = cursor.execute("SELECT username FROM user")
    conn.commit()
    results = rows.fetchall()
    # print(results)

    print("Users:")
    for row in results:
        print(row[0])

    
args = parse_args()
open_and_create()

if args.a and args.p:
    save_new_usernamecorrect(args.a, args.p)
elif args.c and args.p:
    check_for_username_correct(args.c, args.p)
elif args.l:
    print_all_users()

conn.close()


