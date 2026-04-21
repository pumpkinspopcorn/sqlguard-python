# sample_mixed.py

import sqlite3


# =====================================================================
# ORIGINAL SQL TEST CASES
# =====================================================================

# Database Connection (Beginner style)

connection = sqlite3.connect("users.db")
cursor = connection.cursor()

# User Login Feature (SAFE - parameterized)

username = input("Enter username: ")
password = input("Enter password: ")

login_query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(login_query,(username,password))

# Search Feature (VULNERABLE - f-string)

search_term = input("Search user: ")
search_query = f"SELECT * FROM users WHERE username = '{search_term}'"
cursor.execute(search_query)

# Profile Lookup (SAFE - parameterized)

user_id = input("Enter user ID: ")
profile_query = "SELECT * FROM users WHERE id = ?"
cursor.execute(profile_query, (user_id,))

# Update Email (VULNERABLE - format())

new_email = input("Enter new email: ")
update_query = "UPDATE users SET email = '{}' WHERE id = {}".format(new_email, user_id)
cursor.execute(update_query)

# Safe Insert Example (SAFE)

new_user = input("New username: ")
safe_insert = "INSERT INTO users(username) VALUES (?)"
cursor.execute(safe_insert, (new_user,))

# Static Query (SAFE - no user input)

cursor.execute("SELECT COUNT(*) FROM users")

session.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
connection.commit()
connection.close()


# =====================================================================
# ORM TEST CASES
# =====================================================================

# --- Django ORM .raw() with string concatenation (VULNERABLE) ---
# The tainted variable is concatenated directly into the raw SQL string.
# Expected: ORMI HIGH, orm_raw_concat

raw_name = input("Enter name to search: ")
results = User.objects.raw("SELECT * FROM users WHERE name = '" + raw_name + "'")

# --- Django ORM .raw() with pre-built tainted variable (VULNERABLE) ---
# The full query string is assembled before being passed to .raw().
# Expected: ORMI HIGH, orm_raw_direct

raw_search = input("Enter search term: ")
raw_query = "SELECT * FROM users WHERE username = '" + raw_search + "'"
results = User.objects.raw(raw_query)

# --- Django ORM .filter() with tainted input (VULNERABLE) ---
# Tainted value passed to .filter() — risk of regex/lookup injection.
# Expected: ORMI MEDIUM, orm_filter

filter_input = input("Filter by username: ")
results = User.objects.filter(filter_input)

# --- Django ORM .get() with tainted input (VULNERABLE) ---
# Tainted value passed directly to .get().
# Expected: ORMI MEDIUM, orm_filter

lookup_id = input("Enter user ID to look up: ")
user_record = User.objects.get(lookup_id)

# --- SQLAlchemy text() wrapper with concatenation (VULNERABLE) ---
# Tainted input concatenated inside text(), bypassing parameterization.
# Expected: ORMI HIGH, orm_text_wrapper

text_id = input("Enter ID: ")
result = session.execute(text("SELECT * FROM users WHERE id = " + text_id))

# --- Django ORM .raw() with params list (SAFE) ---
# Query string is a plain literal with %s placeholder; tainted value
# is passed separately as a params argument — NOT flagged.

safe_raw_name = input("Enter name: ")
results = User.objects.raw("SELECT * FROM users WHERE name = %s", [safe_raw_name])

# --- SQLAlchemy bindparam() sanitization (SAFE) ---
# bindparam() is in SANITIZATION_FUNCTIONS so safe_bp is marked
# SANITIZED in the symbol table — NOT flagged.

bp_user_id = input("Enter ID: ")
safe_bp = bindparam(bp_user_id)
result = session.execute("SELECT * FROM users WHERE id = :id", {"id": safe_bp})
