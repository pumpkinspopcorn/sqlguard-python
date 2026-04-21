"""
Test file with multiple SQL injection vulnerabilities
"""
import sqlite3

# Vulnerability 1: String concatenation
username = input("Enter username: ")
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor = sqlite3.connect('users.db').cursor()
cursor.execute(query)

# Vulnerability 2: Format string
email = input("Enter email: ")
query2 = "SELECT * FROM users WHERE email = '{}'".format(email)
cursor.execute(query2)

# Vulnerability 3: Direct variable
user_input = input("Enter search term: ")
cursor.execute(user_input)
