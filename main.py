# Import necessary libraries for GUI, database, API calls, and time functions
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import requests
import time
from tkinter import font as tkfont
from datetime import datetime

# API configuration constants
API_KEY = "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"  # Replace with actual API key
MODEL = "mistralai/mistral-7b-instruct"  # AI model to use for question generation

# Color scheme for the application UI
BG_COLOR = "#f0f2f5"  # Background color
PRIMARY_COLOR = "#4a6fa5"  # Primary color for buttons and accents
SECONDARY_COLOR = "#166088"  # Secondary color for hover states
ACCENT_COLOR = "#4fc3f7"  # Accent color for highlights
TEXT_COLOR = "#333333"  # Main text color
ERROR_COLOR = "#e63946"  # Color for errors/warnings
SUCCESS_COLOR = "#2e7d32"  # Color for success messages
ADMIN_COLOR = "#8a2be2"  # Special color for admin interfaces

class QuizApp:
    def __init__(self, root):
        """Initialize the main application window and core components"""
        self.root = root  # Store the root window reference
        self.root.title("Study Buddy Pro")  # Set window title
        self.root.geometry("1900x1000")  # Set initial window size
        self.root.configure(bg=BG_COLOR)  # Set background color
        
        # Font configurations for consistent styling
        self.title_font = tkfont.Font(family="Segoe UI", size=24, weight="bold")  # Title font
        self.button_font = tkfont.Font(family="Segoe UI", size=16)  # Button font
        self.custom_font = tkfont.Font(family="Segoe UI", size=16)  # General text font
        self.small_font = tkfont.Font(family="Segoe UI", size=14)  # Smaller text font
        
        # Database setup - Create connection and cursor
        self.conn = sqlite3.connect('quiz.db')  # Connect to SQLite database
        self.c = self.conn.cursor()  # Create database cursor
        
        # Create users table if it doesn't exist
        self.c.execute('''CREATE TABLE IF NOT EXISTS users
                        (username TEXT PRIMARY KEY, password TEXT)''')
        
        # Create test history table to store test results
        self.c.execute('''CREATE TABLE IF NOT EXISTS test_history
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         username TEXT,
                         subject TEXT,
                         level TEXT,
                         score INTEGER,
                         total_questions INTEGER,
                         time_taken TEXT,
                         date TEXT,
                         FOREIGN KEY(username) REFERENCES users(username))''')
        
        # Create question history table to store individual question results
        self.c.execute('''CREATE TABLE IF NOT EXISTS question_history
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         test_id INTEGER,
                         question_text TEXT,
                         user_answer TEXT,
                         correct_answer TEXT,
                         explanation TEXT,
                         FOREIGN KEY(test_id) REFERENCES test_history(id))''')
        
        # Create user settings table
        self.c.execute('''CREATE TABLE IF NOT EXISTS user_settings
                        (username TEXT PRIMARY KEY,
                         default_question_count INTEGER DEFAULT 10,
                         FOREIGN KEY(username) REFERENCES users(username))''')
        
        self.conn.commit()  # Commit table creations
        
        # Application state variables
        self.current_user = None  # Track logged in user
        self.score = 0  # Current quiz score
        self.quiz_start_time = 0  # Timer start time
        self.timer_running = False  # Timer state flag
        self.selected_level = ""  # User-selected difficulty level
        self.selected_time_limit = "Unlimited"  # Default time limit
        self.questions = []  # Store generated questions
        self.current_question = 0  # Current question index
        self.user_answers = []  # Store user answers during quiz
        self.loading_complete = False  # Loading state flag
        self.current_test_id = None  # Track current test ID
        self.total_questions = 10  # Default number of questions
        
        # Loading bar variables
        self.loading_bar = None  # Loading bar widget
        self.loading_label = None  # Loading text label
        self.loading_progress = 0  # Loading progress percentage
        
        self.show_login_screen()  # Start with login screen

    # ================= DATABASE OPERATIONS =================
    def save_test_results(self):
        """Save the current test results to database"""
        if not self.current_user:  # Ensure user is logged in
            return
            
        # Calculate time taken if quiz was timed
        time_taken = ""
        if self.time_limit > 0:
            elapsed = time.time() - self.quiz_start_time
            mins, secs = divmod(int(elapsed), 60)
            time_taken = f"{mins:02d}:{secs:02d}"
        
        # Insert test record into history table
        self.c.execute('''INSERT INTO test_history 
                        (username, subject, level, score, total_questions, time_taken, date)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (self.current_user, self.subject, self.selected_level, 
                       self.score, self.total_questions, time_taken, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        self.current_test_id = self.c.lastrowid  # Store the new test ID
        
        # Insert all questions into question history
        for item in self.user_answers:
            self.c.execute('''INSERT INTO question_history
                            (test_id, question_text, user_answer, correct_answer, explanation)
                            VALUES (?, ?, ?, ?, ?)''',
                          (self.current_test_id, item["question"], item["user_answer"],
                           item["correct_answer"], item["explanation"]))
        
        self.conn.commit()  # Commit all changes

    def get_user_history(self, username):
        """Get all test history for a specific user"""
        self.c.execute('''SELECT * FROM test_history 
                        WHERE username = ? 
                        ORDER BY date DESC''', (username,))
        return self.c.fetchall()  # Return all matching records
    
    def get_test_questions(self, test_id):
        """Get all questions for a specific test"""
        self.c.execute('''SELECT * FROM question_history
                        WHERE test_id = ?''', (test_id,))
        return self.c.fetchall()  # Return all questions for the test
    
    def get_all_users(self):
        """Get all user accounts (except admin) for admin panel"""
        self.c.execute('''SELECT username FROM users
                        WHERE username != 'admin' 
                        ORDER BY username''')
        return [row[0] for row in self.c.fetchall()]  # Return list of usernames
    
    def delete_user(self, username):
        """Delete a user account and all associated data"""
        try:
            # First delete all question history for the user's tests
            self.c.execute('''DELETE FROM question_history
                            WHERE test_id IN 
                            (SELECT id FROM test_history WHERE username = ?)''', (username,))
            # Then delete the test history
            self.c.execute('''DELETE FROM test_history WHERE username = ?''', (username,))
            # Then delete user settings
            self.c.execute('''DELETE FROM user_settings WHERE username = ?''', (username,))
            # Finally delete the user account
            self.c.execute('''DELETE FROM users WHERE username = ?''', (username,))
            self.conn.commit()  # Commit all deletions
            return True  # Return success
        except Exception as e:
            print(f"Error deleting user: {e}")  # Log error
            return False  # Return failure
    
    def update_admin_credentials(self, new_username, new_password):
        """Update admin username and password"""
        try:
            # First check if new username already exists (if changing username)
            if new_username != "admin":
                self.c.execute("SELECT username FROM users WHERE username=?", (new_username,))
                if self.c.fetchone():
                    return False, "Username already exists"
            
            # Update admin credentials
            self.c.execute("UPDATE users SET username=?, password=? WHERE username='admin'", 
                         (new_username, new_password))
            self.conn.commit()
            return True, "Admin credentials updated successfully"
        except Exception as e:
            return False, f"Error updating credentials: {str(e)}"
            
    def get_user_settings(self, username):
        """Get user settings from database"""
        self.c.execute('''SELECT default_question_count FROM user_settings 
                        WHERE username = ?''', (username,))
        result = self.c.fetchone()
        if result:
            return {"default_question_count": result[0]}
        else:
            # Insert default settings if none exist
            self.c.execute('''INSERT INTO user_settings (username, default_question_count)
                            VALUES (?, 10)''', (username,))
            self.conn.commit()
            return {"default_question_count": 10}
    
    def update_user_settings(self, username, settings):
        """Update user settings in database"""
        try:
            self.c.execute('''UPDATE user_settings SET default_question_count = ?
                            WHERE username = ?''', 
                          (settings["default_question_count"], username))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error updating settings: {e}")
            return False

    # ================= ADMIN FUNCTIONALITY =================
    def show_admin_login(self):
        """Display admin login screen"""
        self.clear_screen()  # Clear current screen
        
        # Create main admin login frame
        admin_frame = tk.Frame(self.root, bg=BG_COLOR)
        admin_frame.pack(pady=150, padx=40, fill="both", expand=True)
        
        # Admin login title
        tk.Label(admin_frame, 
                text="Admin Login", 
                font=self.title_font,
                bg=BG_COLOR,
                fg=ADMIN_COLOR).pack(pady=30)
        
        # Form frame for password entry
        form_frame = tk.Frame(admin_frame, bg=BG_COLOR)
        form_frame.pack(pady=30)
        
        # Password label and entry
        tk.Label(form_frame, 
                text="Admin Password:", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).grid(row=0, column=0, pady=15, sticky="e")
        
        self.admin_pass_entry = ttk.Entry(form_frame, width=30, show="*", font=self.custom_font)
        self.admin_pass_entry.grid(row=0, column=1, pady=15, padx=20)
        
        # Button frame for actions
        button_frame = tk.Frame(admin_frame, bg=BG_COLOR)
        button_frame.pack(pady=40)
        
        # Login button
        ttk.Button(button_frame, 
                  text="Login", 
                  command=self.verify_admin).pack(side="left", padx=20)
        # Back button
        ttk.Button(button_frame, 
                  text="Back", 
                  command=self.show_login_screen).pack(side="left", padx=20)

    def verify_admin(self):
        """Verify admin password and grant access"""
        password = self.admin_pass_entry.get()  # Get entered password
        if password == "adminRyan":  # Check against hardcoded admin password
            self.show_admin_dashboard()  # Show admin dashboard if correct
        else:
            messagebox.showerror("Error", "Incorrect admin password")  # Show error if wrong

    def show_admin_dashboard(self):
        """Display the main admin control panel"""
        self.clear_screen()  # Clear current screen
        
        # Create main admin frame
        admin_frame = tk.Frame(self.root, bg=BG_COLOR)
        admin_frame.pack(pady=30, padx=40, fill="both", expand=True)
        
        # Admin dashboard title
        tk.Label(admin_frame, 
                text="Admin Dashboard", 
                font=self.title_font,
                bg=BG_COLOR,
                fg=ADMIN_COLOR).pack(pady=20)
        
        # Create notebook (tabbed interface)
        admin_notebook = ttk.Notebook(admin_frame)
        admin_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create frames for each tab
        user_frame = tk.Frame(admin_notebook, bg=BG_COLOR)
        admin_info_frame = tk.Frame(admin_notebook, bg=BG_COLOR)
        user_settings_frame = tk.Frame(admin_notebook, bg=BG_COLOR)
        
        # Add tabs to notebook
        admin_notebook.add(user_frame, text="User Management")
        admin_notebook.add(admin_info_frame, text="Admin Info")
        admin_notebook.add(user_settings_frame, text="User Settings")
        
        # ===== User Management Tab =====
        # User management frame
        user_mgmt_frame = tk.LabelFrame(user_frame, text="User Management", 
                                      font=self.custom_font, bg=BG_COLOR)
        user_mgmt_frame.pack(fill="both", expand=True, pady=10, padx=10)
        
        # User list with scrollbar
        list_frame = tk.Frame(user_mgmt_frame, bg=BG_COLOR)
        list_frame.pack(fill="both", expand=True, pady=10)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.user_listbox = tk.Listbox(list_frame,
                                     yscrollcommand=scrollbar.set,
                                     font=self.custom_font,
                                     height=10,
                                     selectmode="single")
        scrollbar.config(command=self.user_listbox.yview)
        
        # Populate user list
        users = self.get_all_users()
        for user in users:
            self.user_listbox.insert("end", user)
        self.user_listbox.pack(fill="both", expand=True)
        
        # User action buttons
        button_frame = tk.Frame(user_mgmt_frame, bg=BG_COLOR)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, 
                  text="View Tests", 
                  command=self.admin_view_user_tests).pack(side="left", padx=10)
        ttk.Button(button_frame, 
                  text="Delete User", 
                  command=self.admin_delete_user).pack(side="left", padx=10)
        ttk.Button(button_frame,
                  text="View Settings",
                  command=self.admin_view_user_settings).pack(side="left", padx=10)
        
        # ===== Admin Info Tab =====
        # Admin info management frame
        info_frame = tk.LabelFrame(admin_info_frame, text="Admin Credentials",
                                 font=self.custom_font, bg=BG_COLOR)
        info_frame.pack(fill="both", expand=True, pady=10, padx=10)
        
        # Current username
        tk.Label(info_frame,
                text="Current Admin Username: admin",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=10)
        
        # New username
        tk.Label(info_frame,
                text="New Username:",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=5)
        self.new_admin_user_entry = ttk.Entry(info_frame, width=30, font=self.custom_font)
        self.new_admin_user_entry.pack(pady=5)
        
        # New password
        tk.Label(info_frame,
                text="New Password:",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=5)
        self.new_admin_pass_entry = ttk.Entry(info_frame, width=30, show="*", font=self.custom_font)
        self.new_admin_pass_entry.pack(pady=5)
        
        # Confirm new password
        tk.Label(info_frame,
                text="Confirm Password:",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=5)
        self.confirm_admin_pass_entry = ttk.Entry(info_frame, width=30, show="*", font=self.custom_font)
        self.confirm_admin_pass_entry.pack(pady=5)
        
        # Update button
        ttk.Button(info_frame,
                  text="Update Credentials",
                  command=self.update_admin_info).pack(pady=15)
        
        # ===== User Settings Tab =====
        # User settings management frame
        settings_frame = tk.LabelFrame(user_settings_frame, text="Manage User Settings",
                                     font=self.custom_font, bg=BG_COLOR)
        settings_frame.pack(fill="both", expand=True, pady=10, padx=10)
        
        # User selection
        tk.Label(settings_frame,
                text="Select User:",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=5)
        
        self.settings_user_var = tk.StringVar()
        self.settings_user_dropdown = ttk.Combobox(settings_frame, 
                                                 textvariable=self.settings_user_var,
                                                 font=self.custom_font,
                                                 state="readonly")
        self.settings_user_dropdown['values'] = self.get_all_users()
        self.settings_user_dropdown.pack(pady=5)
        self.settings_user_dropdown.bind("<<ComboboxSelected>>", self.admin_load_user_settings)
        
        # Default question count
        tk.Label(settings_frame,
                text="Default Question Count:",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=5)
        
        self.admin_question_count_var = tk.IntVar(value=10)
        self.admin_question_count_spin = ttk.Spinbox(settings_frame,
                                                   from_=1, to=50,
                                                   textvariable=self.admin_question_count_var,
                                                   font=self.custom_font)
        self.admin_question_count_spin.pack(pady=5)
        
        # Update button
        ttk.Button(settings_frame,
                  text="Update Settings",
                  command=self.admin_update_user_settings).pack(pady=15)
        
        # Back button to return to login screen
        ttk.Button(admin_frame, 
                  text="Back to Login", 
                  command=self.show_login_screen).pack(pady=20)

    def admin_load_user_settings(self, event=None):
        """Load settings for selected user in admin panel"""
        username = self.settings_user_var.get()
        if username:
            settings = self.get_user_settings(username)
            self.admin_question_count_var.set(settings["default_question_count"])

    def admin_update_user_settings(self):
        """Update user settings from admin panel"""
        username = self.settings_user_var.get()
        if not username:
            messagebox.showerror("Error", "Please select a user")
            return
            
        settings = {
            "default_question_count": self.admin_question_count_var.get()
        }
        
        if self.update_user_settings(username, settings):
            messagebox.showinfo("Success", f"Settings updated for {username}")
        else:
            messagebox.showerror("Error", "Failed to update settings")

    def admin_view_user_settings(self):
        """View and edit settings for selected user"""
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a user")
            return
            
        username = self.user_listbox.get(selection[0])
        self.settings_user_var.set(username)
        self.admin_load_user_settings()
        
        # Switch to the settings tab
        self.admin_notebook.select(2)  # Assuming settings tab is index 2

    def update_admin_info(self):
        """Handle admin credential updates"""
        new_username = self.new_admin_user_entry.get().strip()
        new_password = self.new_admin_pass_entry.get().strip()
        confirm_password = self.confirm_admin_pass_entry.get().strip()
        
        # Validate inputs
        if not new_username or not new_password or not confirm_password:
            messagebox.showerror("Error", "All fields are required")
            return
            
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        # Update admin credentials in database
        success, message = self.update_admin_credentials(new_username, new_password)
        if success:
            messagebox.showinfo("Success", message)
            # Clear fields
            self.new_admin_user_entry.delete(0, "end")
            self.new_admin_pass_entry.delete(0, "end")
            self.confirm_admin_pass_entry.delete(0, "end")
        else:
            messagebox.showerror("Error", message)

    def admin_view_user_tests(self):
        """Show test history for selected user"""
        selection = self.user_listbox.curselection()  # Get selected user
        if not selection:  # Check if a user is selected
            messagebox.showerror("Error", "Please select a user")
            return
            
        username = self.user_listbox.get(selection[0])  # Get username
        tests = self.get_user_history(username)  # Get user's test history
        
        # Create popup window for test history
        test_window = tk.Toplevel(self.root)
        test_window.title(f"Test History for {username}")
        test_window.geometry("800x600")
        test_window.configure(bg=BG_COLOR)
        
        # Window title
        tk.Label(test_window,
                text=f"Test History: {username}",
                font=self.title_font,
                bg=BG_COLOR,
                fg=ADMIN_COLOR).pack(pady=10)
        
        # Create scrollable area
        canvas = tk.Canvas(test_window, bg=BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(test_window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)
        
        # Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Display each test
        for test in tests:
            test_id, _, subject, level, score, total, time_taken, date = test
            
            # Create frame for each test
            test_frame = tk.Frame(scrollable_frame, 
                                bg="white",
                                bd=2,
                                relief="groove",
                                padx=15,
                                pady=15)
            test_frame.pack(fill="x", pady=5, padx=10)
            
            # Test information
            tk.Label(test_frame,
                    text=f"{date} - {subject} ({level})",
                    font=("Segoe UI", 14, "bold"),
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")
            
            tk.Label(test_frame,
                    text=f"Score: {score}/{total} | Time: {time_taken}",
                    font=self.custom_font,
                    bg="white",
                    fg=SECONDARY_COLOR).pack(anchor="w")
            
            # Button to view test details
            ttk.Button(test_frame,
                      text="View Details",
                      command=lambda tid=test_id: self.admin_show_test_details(tid)).pack(anchor="e")

    def admin_show_test_details(self, test_id):
        """Show detailed question results for a specific test"""
        questions = self.get_test_questions(test_id)  # Get all questions for test
        
        # Create detail window
        detail_window = tk.Toplevel(self.root)
        detail_window.title("Test Details")
        detail_window.geometry("900x700")
        detail_window.configure(bg=BG_COLOR)
        
        # Window title
        tk.Label(detail_window,
                text="Test Questions & Answers",
                font=self.title_font,
                bg=BG_COLOR,
                fg=ADMIN_COLOR).pack(pady=10)
        
        # Create scrollable area
        canvas = tk.Canvas(detail_window, bg=BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(detail_window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)
        
        # Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Display each question
        for i, q in enumerate(questions):
            _, _, question_text, user_answer, correct_answer, explanation = q
            
            # Question frame
            q_frame = tk.Frame(scrollable_frame, 
                             bg="white",
                             bd=2,
                             relief="groove",
                             padx=15,
                             pady=15)
            q_frame.pack(fill="x", pady=5, padx=10)
            
            # Question number
            tk.Label(q_frame,
                    text=f"Question {i+1}:",
                    font=("Segoe UI", 14, "bold"),
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")
            
            # Question text
            tk.Label(q_frame,
                    text=question_text,
                    wraplength=800,
                    justify="left",
                    font=self.custom_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w", pady=5)
            
            # User's answer (color-coded for correct/incorrect)
            answer_color = SUCCESS_COLOR if user_answer.upper() == correct_answer.upper() else ERROR_COLOR
            tk.Label(q_frame,
                    text=f"User answer: {user_answer}",
                    font=self.custom_font,
                    bg="white",
                    fg=answer_color).pack(anchor="w")
            
            # Correct answer
            tk.Label(q_frame,
                    text=f"Correct answer: {correct_answer}",
                    font=self.custom_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")
            
            # Explanation
            tk.Label(q_frame,
                    text="Explanation:",
                    font=("Segoe UI", 12, "bold"),
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w", pady=(5,0))
            
            tk.Label(q_frame,
                    text=explanation,
                    wraplength=800,
                    justify="left",
                    font=self.small_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")

    def admin_delete_user(self):
        """Delete selected user after confirmation"""
        selection = self.user_listbox.curselection()  # Get selected user
        if not selection:  # Check if user is selected
            messagebox.showerror("Error", "Please select a user")
            return
            
        username = self.user_listbox.get(selection[0])  # Get username
        
        # Confirm deletion
        if messagebox.askyesno("Confirm", f"Delete user {username} and all their data?"):
            if self.delete_user(username):  # Attempt deletion
                messagebox.showinfo("Success", f"User {username} deleted")
                self.show_admin_dashboard()  # Refresh admin view
            else:
                messagebox.showerror("Error", "Failed to delete user")

    # ================= USER SETTINGS =================
    def show_user_settings(self):
        """Display user account settings screen"""
        self.clear_screen()  # Clear current screen
        
        # Create main settings frame
        settings_frame = tk.Frame(self.root, bg=BG_COLOR)
        settings_frame.pack(pady=60, padx=40, fill="both", expand=True)
        
        # Settings title
        tk.Label(settings_frame, 
                text="Account Settings", 
                font=self.title_font,
                bg=BG_COLOR,
                fg=PRIMARY_COLOR).pack(pady=20)
        
        # ===== Password Change Section =====
        pass_frame = tk.LabelFrame(settings_frame, text="Change Password",
                                 font=self.custom_font, bg=BG_COLOR)
        pass_frame.pack(fill="x", pady=20, padx=20)
        
        # Current password
        tk.Label(pass_frame, 
                text="Current Password:", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).grid(row=0, column=0, pady=10, sticky="e")
        self.current_pass_entry = ttk.Entry(pass_frame, width=30, show="*", font=self.custom_font)
        self.current_pass_entry.grid(row=0, column=1, pady=10, padx=10)
        
        # New password
        tk.Label(pass_frame, 
                text="New Password:", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).grid(row=1, column=0, pady=10, sticky="e")
        self.new_pass_entry = ttk.Entry(pass_frame, width=30, show="*", font=self.custom_font)
        self.new_pass_entry.grid(row=1, column=1, pady=10, padx=10)
        
        # Confirm new password
        tk.Label(pass_frame, 
                text="Confirm New:", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).grid(row=2, column=0, pady=10, sticky="e")
        self.confirm_pass_entry = ttk.Entry(pass_frame, width=30, show="*", font=self.custom_font)
        self.confirm_pass_entry.grid(row=2, column=1, pady=10, padx=10)
        
        # Change password button
        ttk.Button(pass_frame,
                  text="Change Password",
                  command=self.change_password).grid(row=3, column=1, pady=10, sticky="e")
        
        # ===== User Preferences Section =====
        pref_frame = tk.LabelFrame(settings_frame, text="Preferences",
                                 font=self.custom_font, bg=BG_COLOR)
        pref_frame.pack(fill="x", pady=20, padx=20)
        
        # Default question count
        tk.Label(pref_frame,
                text="Default Number of Questions:",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).grid(row=0, column=0, pady=10, sticky="e")
        
        # Get current settings
        settings = self.get_user_settings(self.current_user)
        self.user_question_count_var = tk.IntVar(value=settings["default_question_count"])
        
        self.question_count_spin = ttk.Spinbox(pref_frame,
                                             from_=1, to=50,
                                             textvariable=self.user_question_count_var,
                                             font=self.custom_font)
        self.question_count_spin.grid(row=0, column=1, pady=10, padx=10, sticky="w")
        
        # Save preferences button
        ttk.Button(pref_frame,
                  text="Save Preferences",
                  command=self.save_user_preferences).grid(row=1, column=1, pady=10, sticky="e")
        
        # ===== Test History Section =====
        history_frame = tk.LabelFrame(settings_frame, text="Test History",
                                    font=self.custom_font, bg=BG_COLOR)
        history_frame.pack(fill="x", pady=20, padx=20)
        
        # Get user's test history
        tests = self.get_user_history(self.current_user)
        
        if not tests:  # If no history exists
            tk.Label(history_frame,
                    text="No test history yet",
                    font=self.custom_font,
                    bg=BG_COLOR,
                    fg=TEXT_COLOR).pack(pady=20)
        else:
            # Create scrollable area for history
            canvas = tk.Canvas(history_frame, bg=BG_COLOR, highlightthickness=0)
            scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)
            
            # Configure scrolling
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(
                    scrollregion=canvas.bbox("all")
                )
            )
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Display each test
            for test in tests:
                test_id, _, subject, level, score, total, time_taken, date = test
                
                # Test frame
                test_item = tk.Frame(scrollable_frame, 
                                   bg="white",
                                   bd=2,
                                   relief="groove",
                                   padx=15,
                                   pady=15)
                test_item.pack(fill="x", pady=5, padx=10)
                
                # Test information
                tk.Label(test_item,
                        text=f"{date} - {subject} ({level})",
                        font=("Segoe UI", 14, "bold"),
                        bg="white",
                        fg=TEXT_COLOR).pack(anchor="w")
                
                tk.Label(test_item,
                        text=f"Score: {score}/{total} | Time: {time_taken}",
                        font=self.custom_font,
                        bg="white",
                        fg=SECONDARY_COLOR).pack(anchor="w")
                
                # Review button
                ttk.Button(test_item,
                          text="Review Test",
                          command=lambda tid=test_id: self.show_test_review(tid)).pack(anchor="e")
        
        # Back button
        ttk.Button(settings_frame,
                  text="Back to Main Menu",
                  command=self.show_subject_screen).pack(pady=20)

    def save_user_preferences(self):
        """Save user preferences from settings screen"""
        settings = {
            "default_question_count": self.user_question_count_var.get()
        }
        
        if self.update_user_settings(self.current_user, settings):
            messagebox.showinfo("Success", "Preferences saved successfully")
        else:
            messagebox.showerror("Error", "Failed to save preferences")

    def change_password(self):
        """Handle user password change"""
        current = self.current_pass_entry.get()  # Get current password
        new = self.new_pass_entry.get()  # Get new password
        confirm = self.confirm_pass_entry.get()  # Get confirmation
        
        # Validate inputs
        if not current or not new or not confirm:
            messagebox.showerror("Error", "Please fill all fields")
            return
            
        if new != confirm:  # Check if new passwords match
            messagebox.showerror("Error", "New passwords don't match")
            return
            
        # Verify current password
        self.c.execute("SELECT password FROM users WHERE username=?", (self.current_user,))
        result = self.c.fetchone()
        
        if not result or result[0] != current:  # Check if current password is correct
            messagebox.showerror("Error", "Incorrect current password")
            return
            
        # Update password in database
        self.c.execute("UPDATE users SET password=? WHERE username=?", (new, self.current_user))
        self.conn.commit()
        
        # Show success and clear fields
        messagebox.showinfo("Success", "Password changed successfully")
        self.current_pass_entry.delete(0, "end")
        self.new_pass_entry.delete(0, "end")
        self.confirm_pass_entry.delete(0, "end")

    def show_test_review(self, test_id):
        """Show detailed review of a specific test"""
        questions = self.get_test_questions(test_id)  # Get all questions
        
        # Create review window
        review_window = tk.Toplevel(self.root)
        review_window.title("Test Review")
        review_window.geometry("900x700")
        review_window.configure(bg=BG_COLOR)
        
        # Window title
        tk.Label(review_window,
                text="Test Review",
                font=self.title_font,
                bg=BG_COLOR,
                fg=PRIMARY_COLOR).pack(pady=10)
        
        # Create scrollable area
        canvas = tk.Canvas(review_window, bg=BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(review_window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)
        
        # Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Display each question
        for i, q in enumerate(questions):
            _, _, question_text, user_answer, correct_answer, explanation = q
            
            # Question frame
            q_frame = tk.Frame(scrollable_frame, 
                             bg="white",
                             bd=2,
                             relief="groove",
                             padx=15,
                             pady=15)
            q_frame.pack(fill="x", pady=5, padx=10)
            
            # Question number
            tk.Label(q_frame,
                    text=f"Question {i+1}:",
                    font=("Segoe UI", 14, "bold"),
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")
            
            # Question text
            tk.Label(q_frame,
                    text=question_text,
                    wraplength=800,
                    justify="left",
                    font=self.custom_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w", pady=5)
            
            # User's answer (color-coded)
            answer_color = SUCCESS_COLOR if user_answer.upper() == correct_answer.upper() else ERROR_COLOR
            tk.Label(q_frame,
                    text=f"Your answer: {user_answer}",
                    font=self.custom_font,
                    bg="white",
                    fg=answer_color).pack(anchor="w")
            
            # Correct answer
            tk.Label(q_frame,
                    text=f"Correct answer: {correct_answer}",
                    font=self.custom_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")
            
            # Explanation
            tk.Label(q_frame,
                    text="Explanation:",
                    font=("Segoe UI", 12, "bold"),
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w", pady=(5,0))
            
            tk.Label(q_frame,
                    text=explanation,
                    wraplength=800,
                    justify="left",
                    font=self.small_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")

    # ================= MAIN APPLICATION FUNCTIONS =================
    def apply_styles(self):
        """Configure visual styles for all widgets"""
        style = ttk.Style()  # Create style object
        
        # Button styling
        style.configure("TButton", 
                       font=self.button_font,  # Set font
                       padding=10,  # Add padding
                       background=PRIMARY_COLOR,  # Background color
                       foreground="white")  # Text color
        # Button hover effects
        style.map("TButton",
                background=[('active', SECONDARY_COLOR)],  # Color change on hover
                foreground=[('active', 'white')])
        
        # Entry field styling
        style.configure("TEntry",
                      font=self.custom_font,  # Set font
                      padding=8)  # Add padding
        
        # Progress bar styling
        style.configure("Horizontal.TProgressbar",
                       thickness=30,  # Set height
                       troughcolor=BG_COLOR,  # Background color
                       background=PRIMARY_COLOR,  # Progress color
                       troughrelief='flat',  # Flat style
                       borderwidth=0)  # No border

    def show_loading_screen(self, message="Loading..."):
        """Display loading screen with progress bar"""
        self.clear_screen()  # Clear current screen
        
        # Create loading frame
        loading_frame = tk.Frame(self.root, bg=BG_COLOR)
        loading_frame.pack(expand=True, fill="both", pady=200)
        
        # Loading message
        self.loading_label = tk.Label(loading_frame,
                                    text=message,
                                    font=self.title_font,
                                    bg=BG_COLOR,
                                    fg=PRIMARY_COLOR)
        self.loading_label.pack(pady=20)
        
        # Progress bar
        self.loading_bar = ttk.Progressbar(loading_frame,
                                         orient="horizontal",
                                         length=400,
                                         mode="determinate",
                                         style="Horizontal.TProgressbar")
        self.loading_bar.pack(pady=10)
        
        # Percentage label
        self.loading_percent = tk.Label(loading_frame,
                                      text="0%",
                                      font=self.custom_font,
                                      bg=BG_COLOR,
                                      fg=TEXT_COLOR)
        self.loading_percent.pack()
        
        self.root.update()  # Force UI update

    def update_loading_bar(self, increment=5):
        """Animate loading bar progress"""
        if self.loading_progress < 100:  # If not complete
            self.loading_progress += increment  # Increment progress
            if self.loading_progress > 100:  # Don't exceed 100%
                self.loading_progress = 100
            
            # Update progress bar and label
            self.loading_bar['value'] = self.loading_progress
            self.loading_percent.config(text=f"{self.loading_progress}%")
            # Schedule next update
            self.root.after(50, self.update_loading_bar)
        else:
            self.loading_complete = True  # Mark as complete

    def show_login_screen(self):
        """Display login/registration screen"""
        self.clear_screen()  # Clear current screen
        self.apply_styles()  # Apply styles
        
        # Create main login frame
        login_frame = tk.Frame(self.root, bg=BG_COLOR)
        login_frame.pack(pady=80, padx=40, fill="both", expand=True)
        
        # Application title
        tk.Label(login_frame, 
                text="Welcome to Study Buddy Pro!", 
                font=self.title_font,
                bg=BG_COLOR,
                fg=PRIMARY_COLOR).pack(pady=40)
        
        # Admin login button
        ttk.Button(login_frame,
                  text="Admin Login",
                  command=self.show_admin_login).pack(pady=10)
        
        # Form frame for credentials
        form_frame = tk.Frame(login_frame, bg=BG_COLOR)
        form_frame.pack(pady=30)
        
        # Username field
        tk.Label(form_frame, 
                text="Username:", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).grid(row=0, column=0, pady=15, sticky="e")
        self.username_entry = ttk.Entry(form_frame, width=30, font=self.custom_font)
        self.username_entry.grid(row=0, column=1, pady=15, padx=20)
        
        # Password field
        tk.Label(form_frame, 
                text="Password:", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).grid(row=1, column=0, pady=15, sticky="e")
        self.password_entry = ttk.Entry(form_frame, width=30, show="*", font=self.custom_font)
        self.password_entry.grid(row=1, column=1, pady=15, padx=20)
        
        # Button frame for actions
        button_frame = tk.Frame(login_frame, bg=BG_COLOR)
        button_frame.pack(pady=40)
        
        # Login button
        ttk.Button(button_frame, 
                  text="Log In", 
                  command=self.login).pack(side="left", padx=20)
        # Register button
        ttk.Button(button_frame, 
                  text="Sign Up", 
                  command=self.register).pack(side="left", padx=20)

    def login(self):
        """Handle user login"""
        username = self.username_entry.get().strip()  # Get username
        password = self.password_entry.get().strip()  # Get password
        
        # Validate inputs
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        # Check credentials against database
        self.c.execute("SELECT * FROM users WHERE username=? AND password=?", 
                      (username, password))
        if self.c.fetchone():  # If match found
            self.current_user = username  # Set current user
            self.score = 0  # Reset score
            
            # Load user settings
            settings = self.get_user_settings(username)
            self.total_questions = settings["default_question_count"]
            
            self.show_loading_screen("Loading your dashboard...")  # Show loading
            self.update_loading_bar()  # Start progress bar
            self.root.after(2000, self.show_subject_screen)  # Proceed after delay
        else:
            messagebox.showerror("Error", "Invalid credentials")  # Show error

    def register(self):
        """Handle new user registration"""
        username = self.username_entry.get().strip()  # Get username
        password = self.password_entry.get().strip()  # Get password
        
        # Validate inputs
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        try:
            # Attempt to create new account
            self.c.execute("INSERT INTO users VALUES (?, ?)", (username, password))
            self.conn.commit()  # Save changes
            messagebox.showinfo("Success", "Account created! Please login.")
        except sqlite3.IntegrityError:  # If username exists
            messagebox.showerror("Error", "Username already exists")

    def show_subject_screen(self):
        """Display subject selection screen"""
        if not self.loading_complete:  # Wait for loading to complete
            self.root.after(100, self.show_subject_screen)
            return
            
        self.clear_screen()  # Clear current screen
        self.apply_styles()  # Apply styles
        
        # Create main subject frame
        subject_frame = tk.Frame(self.root, bg=BG_COLOR)
        subject_frame.pack(pady=60, padx=40, fill="both", expand=True)
        
        # Welcome message
        tk.Label(subject_frame, 
                text=f"Welcome, {self.current_user}!", 
                font=self.title_font,
                bg=BG_COLOR,
                fg=PRIMARY_COLOR).pack(pady=30)
        
        # Subject entry
        tk.Label(subject_frame, 
                text="Enter subject/topic:", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=10)
        self.subject_entry = ttk.Entry(subject_frame, width=30, font=self.custom_font)
        self.subject_entry.pack(pady=10)
        
        # Level entry (flexible format)
        tk.Label(subject_frame,
                text="Enter level (e.g., 'Grade 5', 'Beginner', 'Advanced'):",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=10)
        self.level_entry = ttk.Entry(subject_frame, width=30, font=self.custom_font)
        self.level_entry.pack(pady=10)
        
        # Number of questions selection
        tk.Label(subject_frame,
                text="Number of questions:",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=10)
        
        self.question_count_var = tk.IntVar(value=self.total_questions)
        self.question_count_spin = ttk.Spinbox(subject_frame,
                                             from_=1, to=50,
                                             textvariable=self.question_count_var,
                                             font=self.custom_font)
        self.question_count_spin.pack(pady=10)
        
        # Time limit selection
        tk.Label(subject_frame,
                text="Select time limit:",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(pady=10)
        
        self.time_var = tk.StringVar(value="Unlimited")  # Default value
        time_options = ["1 minute", "3 minutes", "5 minutes", "Unlimited"]  # Options
        time_menu = ttk.OptionMenu(subject_frame, self.time_var, 
                                  time_options[-1], *time_options)  # Create menu
        time_menu.pack(pady=10)
        
        # Start quiz button
        ttk.Button(subject_frame,
                  text="Start Quiz",
                  command=self.prepare_quiz).pack(pady=30)
        
        # User settings button
        ttk.Button(subject_frame,
                  text="Account Settings",
                  command=self.show_user_settings).pack(side="left", padx=10)
        
        # Logout button
        ttk.Button(subject_frame, 
                  text="Logout", 
                  command=self.show_login_screen).pack(side="right", padx=10)

    def prepare_quiz(self):
        """Prepare quiz settings and start"""
        self.subject = self.subject_entry.get().strip()  # Get subject
        self.selected_level = self.level_entry.get().strip()  # Get level
        self.selected_time_limit = self.time_var.get()  # Get time limit
        self.total_questions = self.question_count_var.get()  # Get question count
        
        # Validate inputs
        if not self.subject:
            messagebox.showerror("Error", "Please enter a subject")
            return
            
        if not self.selected_level:
            messagebox.showerror("Error", "Please enter a level")
            return
            
        if self.total_questions < 1 or self.total_questions > 50:
            messagebox.showerror("Error", "Please select between 1-50 questions")
            return
        
        # Convert time limit to seconds
        time_limits = {
            "1 minute": 60,
            "3 minutes": 180,
            "5 minutes": 300,
            "Unlimited": 0
        }
        self.time_limit = time_limits[self.selected_time_limit]
        
        # Initialize quiz variables
        self.questions = []  # Clear questions
        self.current_question = 0  # Reset question index
        self.score = 0  # Reset score
        self.user_answers = []  # Clear previous answers
        self.quiz_start_time = time.time()  # Record start time
        
        # Start timer if not unlimited
        if self.time_limit > 0:
            self.timer_running = True
            self.update_timer()
        
        # Show loading screen and start quiz
        self.show_loading_screen("Generating your quiz...")
        self.update_loading_bar()
        self.root.after(2000, self.generate_question)

    def update_timer(self):
        """Update and display remaining quiz time"""
        if not self.timer_running:  # If timer stopped
            return
            
        elapsed = time.time() - self.quiz_start_time  # Calculate elapsed time
        remaining = max(0, self.time_limit - elapsed)  # Calculate remaining time
        
        # Format time as MM:SS
        mins, secs = divmod(int(remaining), 60)
        time_str = f"{mins:02d}:{secs:02d}"
        
        # Update timer label if it exists
        if hasattr(self, 'timer_label'):
            self.timer_label.config(text=f"Time remaining: {time_str}")
        
        # Check if time is up
        if remaining <= 0:
            self.timer_running = False
            self.end_quiz()
        else:
            # Schedule next update in 1 second
            self.root.after(1000, self.update_timer)

    def generate_question(self):
        """Generate a new question using API"""
        if not self.loading_complete:  # Wait for loading to complete
            self.root.after(100, self.generate_question)
            return
            
        try:
            # Create prompt for AI question generation
            prompt = f"""Create one {self.subject} multiple-choice question suitable for {self.selected_level} level with these requirements: 
            1. Number the question (e.g., '1. What is...')
            2. Include 4 options labeled A, B, C, D with full text answers
            3. At the end, add: 'Correct answer: X' (replace X with the correct option)
            4. After that, add: 'Explanation: [detailed explanation of the answer]'"""
            
            # Make API request to generate question
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {API_KEY}"},
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=20  # 20 second timeout
            )
            
            # Check for API errors
            if response.status_code != 200:
                raise Exception(f"API Error: {response.text}")
            
            # Extract question text from response
            full_question = response.json()["choices"][0]["message"]["content"]
            
            # Parse the response to separate components
            correct_marker = "Correct answer: "
            explanation_marker = "Explanation: "
            
            # Find positions of markers in text
            correct_index = full_question.find(correct_marker)
            explanation_index = full_question.find(explanation_marker)
            
            # Validate question format
            if correct_index == -1 or explanation_index == -1:
                raise Exception("Couldn't parse question format")
            
            # Extract correct answer (first character after marker)
            correct_answer = full_question[correct_index + len(correct_marker):explanation_index].strip()[0]
            # Extract explanation (everything after explanation marker)
            explanation = full_question[explanation_index + len(explanation_marker):].strip()
            # Extract question text (everything before correct answer marker)
            question_text = full_question[:correct_index].strip()
            
            # Store question data
            self.questions.append({
                "text": question_text,
                "correct": correct_answer,
                "explanation": explanation,
                "full_text": full_question
            })
            
            # Display the generated question
            self.show_question()
            
        except Exception as e:
            # Handle any errors during question generation
            messagebox.showerror("Error", f"Failed to generate question:\n{str(e)}")
            self.show_subject_screen()

    def show_question(self):
        """Display the current question"""
        self.clear_screen()  # Clear current screen
        self.apply_styles()  # Apply styles
        
        # Create main quiz frame
        quiz_frame = tk.Frame(self.root, bg=BG_COLOR)
        quiz_frame.pack(pady=30, padx=40, fill="both", expand=True)
        
        # Header frame with subject, score, and timer
        header_frame = tk.Frame(quiz_frame, bg=BG_COLOR)
        header_frame.pack(fill="x", pady=20)
        
        # Subject and level display
        tk.Label(header_frame, 
                text=f"Subject: {self.subject} | Level: {self.selected_level}", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=SECONDARY_COLOR).pack(side="left")
        
        # Current score display
        tk.Label(header_frame, 
                text=f"Score: {self.score}", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=SECONDARY_COLOR).pack(side="right")
        
        # Timer display (if timed quiz)
        if self.time_limit > 0:
            self.timer_label = tk.Label(header_frame,
                                      font=self.custom_font,
                                      bg=BG_COLOR,
                                      fg=SECONDARY_COLOR)
            self.timer_label.pack(side="right", padx=20)
            self.update_timer()  # Start/update timer
        
        # Get current question data
        question = self.questions[self.current_question]
        
        # Question display frame
        question_frame = tk.Frame(quiz_frame, bg=BG_COLOR)
        question_frame.pack(pady=30, fill="x")
        
        # Display question number
        tk.Label(question_frame, 
                text=f"Question {self.current_question + 1} of {self.total_questions}", 
                font=("Segoe UI", 16, "bold"),
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(anchor="w", pady=(0,10))
        
        # Display question text with word wrapping
        tk.Label(question_frame, 
                text=question["text"], 
                wraplength=800,
                justify='left',
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(anchor="w")
        
        # Answer input frame
        answer_frame = tk.Frame(quiz_frame, bg=BG_COLOR)
        answer_frame.pack(pady=30)
        
        # Answer prompt label
        tk.Label(answer_frame, 
                text="Your answer (A/B/C/D or full text):", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(side="left")
        
        # Answer entry field
        self.answer_entry = ttk.Entry(answer_frame, 
                                    font=self.custom_font, 
                                    width=20)
        self.answer_entry.pack(side="left", padx=20)
        
        # Button frame
        button_frame = tk.Frame(quiz_frame, bg=BG_COLOR)
        button_frame.pack(pady=30)
        
        # Submit answer button
        ttk.Button(button_frame, 
                  text="Submit Answer", 
                  command=self.check_answer).pack(side="left", padx=20)
        
        # End test button
        ttk.Button(button_frame,
                  text="End Test",
                  command=self.confirm_end_test).pack(side="left", padx=20)

    def check_answer(self):
        """Validate and check user's answer"""
        user_answer = self.answer_entry.get().strip()  # Get user's answer
        question = self.questions[self.current_question]  # Get current question
        
        # Store user's answer for review
        self.user_answers.append({
            "question": question["text"],
            "user_answer": user_answer,
            "correct_answer": question["correct"],
            "explanation": question["explanation"],
            "full_text": question["full_text"]
        })
        
        # Check if answer is empty
        if not user_answer:
            messagebox.showerror("Error", "Please enter an answer")
            return
            
        # Check if answer is valid (either A/B/C/D or full option text)
        options = self.extract_options(question["full_text"])
        valid_answers = ['A', 'B', 'C', 'D']
        
        # Check if user entered full text of an option
        full_text_match = False
        for letter, text in options.items():
            if user_answer.upper() == text.upper():  # Case-insensitive comparison
                user_answer = letter  # Convert to letter if full text matches
                full_text_match = True
                break
        
        # Validate answer format
        if user_answer.upper() not in valid_answers and not full_text_match:
            messagebox.showerror("Error", "Please enter A, B, C, D or the full answer text")
            return
            
        # Create result window
        result_window = tk.Toplevel(self.root)
        result_window.title("Result")
        result_window.geometry("600x400")
        result_window.configure(bg=BG_COLOR)
        
        # Determine if answer was correct
        if user_answer.upper() == question["correct"].upper():
            self.score += 1  # Increment score
            result_text = f"✅ Correct! (+1 point)"
            color = SUCCESS_COLOR  # Green for correct
        else:
            result_text = f"❌ Incorrect! The correct answer was {question['correct']}"
            color = ERROR_COLOR  # Red for incorrect
        
        # Result header
        tk.Label(result_window, 
                text=result_text, 
                font=self.title_font,
                bg=BG_COLOR,
                fg=color).pack(pady=20)
        
        # Explanation frame
        explanation_frame = tk.Frame(result_window, bg=BG_COLOR)
        explanation_frame.pack(pady=20, padx=30, fill="both", expand=True)
        
        # Explanation label
        tk.Label(explanation_frame, 
                text="Explanation:", 
                font=("Segoe UI", 16, "bold"),
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(anchor="w")
        
        # Explanation text with word wrapping
        tk.Label(explanation_frame, 
                text=question["explanation"], 
                wraplength=550,
                justify='left',
                font=self.custom_font,
                bg=BG_COLOR,
                fg=TEXT_COLOR).pack(anchor="w")
        
        # Current score display
        tk.Label(result_window, 
                text=f"Your current score: {self.score}", 
                font=self.custom_font,
                bg=BG_COLOR,
                fg=SECONDARY_COLOR).pack(pady=20)
        
        def continue_quiz():
            """Handle continuation to next question or end of quiz"""
            result_window.destroy()  # Close result window
            self.current_question += 1  # Move to next question
            
            # Check if reached end of quiz
            if self.current_question >= self.total_questions:
                self.save_test_results()  # Save results
                self.end_quiz()  # End quiz
            else:
                # Generate next question
                self.show_loading_screen("Generating next question...")
                self.loading_progress = 0
                self.loading_complete = False
                self.update_loading_bar()
                self.root.after(2000, self.generate_question)
        
        # Continue button
        ttk.Button(result_window, 
                  text="Continue", 
                  command=continue_quiz).pack(pady=20)

    def extract_options(self, question_text):
        """Extract answer options from question text"""
        options = {}  # Dictionary to store options
        lines = question_text.split('\n')  # Split text by lines
        
        # Process each line to find options
        for line in lines:
            line = line.strip()  # Remove whitespace
            if line.startswith(('A.', 'B.', 'C.', 'D.')):  # Check for option markers
                parts = line.split('.', 1)  # Split at first period
                if len(parts) == 2:  # If properly formatted
                    options[parts[0].strip()] = parts[1].strip()  # Store option
        
        return options

    def confirm_end_test(self):
        """Confirm before ending test early"""
        if messagebox.askyesno("Confirm", "Are you sure you want to end the test?"):
            self.save_test_results()  # Save partial results
            self.end_quiz()  # End quiz

    def end_quiz(self):
        """Handle quiz completion"""
        self.timer_running = False  # Stop timer
        
        # Calculate time taken if timed quiz
        time_taken = ""
        if self.time_limit > 0:
            elapsed = time.time() - self.quiz_start_time
            mins, secs = divmod(int(elapsed), 60)
            time_taken = f"{mins:02d}:{secs:02d}"
        
        # Show results summary
        result_message = f"Quiz completed!\n{time_taken}Final score: {self.score}/{self.total_questions}"
        messagebox.showinfo("Results", result_message)
        
        self.show_review_screen()  # Show review screen

    def show_review_screen(self):
        """Display review screen with all questions and answers"""
        self.clear_screen()  # Clear current screen
        self.apply_styles()  # Apply styles
        
        # Create main review frame
        review_frame = tk.Frame(self.root, bg=BG_COLOR)
        review_frame.pack(pady=30, padx=40, fill="both", expand=True)
        
        # Review title
        tk.Label(review_frame,
                text="Quiz Review",
                font=self.title_font,
                bg=BG_COLOR,
                fg=PRIMARY_COLOR).pack(pady=20)
        
        # Score display
        tk.Label(review_frame,
                text=f"Final Score: {self.score}/{self.total_questions}",
                font=self.custom_font,
                bg=BG_COLOR,
                fg=SECONDARY_COLOR).pack(pady=10)
        
        # Create scrollable area
        canvas = tk.Canvas(review_frame, bg=BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(review_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)
        
        # Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Display each question
        for i, item in enumerate(self.user_answers):
            # Question frame
            q_frame = tk.Frame(scrollable_frame, 
                             bg="white",
                             bd=2,
                             relief="groove",
                             padx=20,
                             pady=20)
            q_frame.pack(fill="x", pady=10, padx=10)
            
            # Question number
            tk.Label(q_frame,
                    text=f"Question {i+1}:",
                    font=("Segoe UI", 14, "bold"),
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")
            
            # Question text
            tk.Label(q_frame,
                    text=item["question"],
                    wraplength=700,
                    justify="left",
                    font=self.custom_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w", pady=10)
            
            # User's answer (color-coded)
            answer_color = SUCCESS_COLOR if item["user_answer"].upper() == item["correct_answer"].upper() else ERROR_COLOR
            tk.Label(q_frame,
                    text=f"Your answer: {item['user_answer']}",
                    font=self.custom_font,
                    bg="white",
                    fg=answer_color).pack(anchor="w")
            
            # Correct answer
            tk.Label(q_frame,
                    text=f"Correct answer: {item['correct_answer']}",
                    font=self.custom_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")
            
            # Explanation
            tk.Label(q_frame,
                    text="Explanation:",
                    font=("Segoe UI", 14, "bold"),
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w", pady=(10,0))
            
            tk.Label(q_frame,
                    text=item["explanation"],
                    wraplength=700,
                    justify="left",
                    font=self.custom_font,
                    bg="white",
                    fg=TEXT_COLOR).pack(anchor="w")
        
        # Button frame
        button_frame = tk.Frame(review_frame, bg=BG_COLOR)
        button_frame.pack(pady=30)
        
        # Back to subjects button
        ttk.Button(button_frame,
                  text="Back to Subjects",
                  command=self.show_subject_screen).pack(side="left", padx=10)
        
        # Account settings button
        ttk.Button(button_frame,
                  text="Account Settings",
                  command=self.show_user_settings).pack(side="left", padx=10)

    def clear_screen(self):
        """Remove all widgets from the screen"""
        for widget in self.root.winfo_children():
            widget.destroy()  # Destroy each widget
        self.loading_complete = True  # Reset loading state
        self.loading_progress = 0  # Reset loading progress

# Main entry point
if __name__ == "__main__":
    root = tk.Tk()  # Create main window
    app = QuizApp(root)  # Create application instance
    root.mainloop()  # Start event loop
    app.conn.close()  # Close database connection when done