import os
import mysql.connector
from dotenv import load_dotenv

def init_database():
    # Load environment variables
    load_dotenv()
    
    # Get database configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME = os.getenv('DB_NAME', 'storefront_builder')
    
    try:
        # Connect to MySQL server
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        print(f"Database '{DB_NAME}' created or already exists.")
        
        # Use the database
        cursor.execute(f"USE {DB_NAME}")
        
        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(256) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'user',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                amount DECIMAL(10, 2) NOT NULL,
                type VARCHAR(10) NOT NULL,
                description VARCHAR(200),
                date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_id INT NOT NULL,
                source_type VARCHAR(20),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(50) NOT NULL,
                type VARCHAR(10) NOT NULL,
                user_id INT,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transaction_categories (
                transaction_id INT NOT NULL,
                category_id INT NOT NULL,
                PRIMARY KEY (transaction_id, category_id),
                FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id INT PRIMARY KEY,
                currency VARCHAR(3) DEFAULT 'USD',
                language VARCHAR(5) DEFAULT 'en',
                theme VARCHAR(20) DEFAULT 'light',
                notification_enabled BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Insert default categories
        cursor.execute("""
            INSERT IGNORE INTO categories (name, type) VALUES
            ('Salary', 'income'),
            ('Freelance', 'income'),
            ('Investments', 'income'),
            ('Food', 'expense'),
            ('Transportation', 'expense'),
            ('Housing', 'expense'),
            ('Utilities', 'expense'),
            ('Entertainment', 'expense'),
            ('Shopping', 'expense'),
            ('Healthcare', 'expense')
        """)
        
        conn.commit()
        print("Database tables created successfully!")
        
    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
            print("Database connection closed.")

if __name__ == '__main__':
    init_database() 