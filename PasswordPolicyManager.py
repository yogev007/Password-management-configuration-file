import hashlib
import sqlite3


def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def check_dictionary(password):
    """Check if the password is a common word or phrase in the dictionary."""
    try:
        with open('dictionary.txt', 'r') as f:
            common_words = f.read().splitlines()
        if password.lower() in common_words:
            return False, "Password must not be a common word or phrase."
        return True, "Password is valid."
    except FileNotFoundError:
        print("Dictionary file not found. Skipping dictionary check.")
        return True, "Dictionary check skipped."
    except Exception as e:
        print(f"Error reading dictionary file: {e}")
        return True, "Error in dictionary check."


class PasswordPolicyManager:
    def __init__(self, db_name='password_config.db'):
        self.db_name = db_name
        try:
            self.initialize_database()
        except sqlite3.Error as e:
            print(f"Error during database initialization: {e}")

    def initialize_database(self):
        """Initialize the database with default settings and required tables."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                # Create password policy table
                cursor.execute(''' 
                    CREATE TABLE IF NOT EXISTS password_policy (
                        setting TEXT PRIMARY KEY,
                        value TEXT
                    )
                ''')
                # Create password history table
                cursor.execute(''' 
                    CREATE TABLE IF NOT EXISTS password_history (
                        username TEXT,
                        password_hash TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                default_values = [
                    ('min_length', '10'),
                    ('require_complexity', 'uppercase, lowercase, digits, special_characters'),
                    ('history', '3'),
                    ('dictionary_prevention', 'true'),
                    ('login_attempts', '3')  # Add setting for login attempts
                ]
                cursor.executemany('INSERT OR REPLACE INTO password_policy (setting, value) VALUES (?, ?)',
                                   default_values)
        except sqlite3.Error as e:
            print(f"Error creating the tables or inserting default values: {e}")
            raise

    def check_password_history(self, username, password):
        """Check if the new password matches any of the user's recent passwords."""
        history_limit = int(self.read_setting('history') or 3)
        password_hash = hash_password(password)

        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT password_hash FROM password_history
                    WHERE username = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (username, history_limit))
                recent_passwords = [row[0] for row in cursor.fetchall()]

            if password_hash in recent_passwords:
                return False, "The new password must not match any of your recent passwords."
            return True, "Password is valid."
        except sqlite3.Error as e:
            print(f"Error checking password history: {e}")
            return False, "Error checking password history."

    def check_password_complexity(self, password):
        """Check if the password meets the complexity requirements."""
        complexity_criteria = self.read_setting('require_complexity') or ''
        complexity_criteria = complexity_criteria.split(', ')

        if 'uppercase' in complexity_criteria and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter."
        if 'lowercase' in complexity_criteria and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter."
        if 'digits' in complexity_criteria and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit."
        if 'special_characters' in complexity_criteria and not any(
                c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for c in password):
            return False, "Password must contain at least one special character."

        return True, "Password meets complexity requirements."

    def update_password(self, username, new_password):
        """Update the user's password and store it in the history."""

        # Check password length
        min_length = int(self.read_setting('min_length') or 10)
        if len(new_password) < min_length:
            return f"Password must be at least {min_length} characters long."

        # Check password history
        is_valid_history, message = self.check_password_history(username, new_password)
        if not is_valid_history:
            return message

        # Check dictionary for common words
        is_valid_dict, message = check_dictionary(new_password)
        if not is_valid_dict:
            return message

        # Check password complexity
        is_valid_complexity, message = self.check_password_complexity(new_password)
        if not is_valid_complexity:
            return message

        password_hash = hash_password(new_password)
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                # Insert the new password into the history
                cursor.execute('''
                    INSERT INTO password_history (username, password_hash)
                    VALUES (?, ?)
                ''', (username, password_hash))

                # Delete old passwords if history exceeds the limit
                history_limit = int(self.read_setting('history') or 3)
                cursor.execute('''
                    DELETE FROM password_history
                    WHERE username = ?
                    AND rowid NOT IN (
                        SELECT rowid FROM password_history
                        WHERE username = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    )
                ''', (username, username, history_limit))

            return "Password updated successfully."
        except sqlite3.Error as e:
            print(f"Error updating password: {e}")
            return "Error updating password."

    def read_setting(self, setting):
        """Retrieve the value of a specific setting."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT value FROM password_policy WHERE setting = ?', (setting,))
                result = cursor.fetchone()
            return result[0] if result else None
        except sqlite3.Error as e:
            print(f"Error retrieving the setting '{setting}': {e}")
            return None

    def check_login_attempts(self, username):
        """Check if the number of login attempts exceeds the allowed limit."""
        login_attempts = int(self.read_setting('login_attempts') or 3)

        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM login_attempts
                    WHERE username = ? AND successful = 0
                ''', (username,))
                failed_attempts = cursor.fetchone()[0]

            if failed_attempts >= login_attempts:
                return False, "Too many failed login attempts. Please try again later."
            return True, "Login attempts are valid."
        except sqlite3.Error as e:
            print(f"Error checking login attempts: {e}")
            return False, "Error checking login attempts."
