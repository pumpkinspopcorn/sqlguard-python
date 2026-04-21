# sample_target.py

username = input("Enter username: ")
query = "SELECT * FROM users WHERE name = " + username
cursor.execute(query)