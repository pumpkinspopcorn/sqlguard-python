# sample_safe.py

user_id = input("Enter ID: ")
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))