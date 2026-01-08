from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException, UnexpectedAlertPresentException
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import traceback
import re
import logging
import json  # For potential JSON validation (optional)
import socket

# Set up logging to file
logging.basicConfig(
    filename='/home/admin/autoLogin.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

# Set up headless Chrome
options = Options()
options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")

# Service setup
service = Service(executable_path='/home/admin/drivers/chromedriver-linux64/chromedriver')

# Global variables
driver = None
observer = None
baseline_cookies = {}

def get_ip_address():
    """Retrieve the local IP address by connecting to an external host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        return ip
    except Exception as e:
        logging.error(f"Failed to get local IP: {e}")
        raise
    finally:
        s.close()

def check_logout_and_update_file():
    """Check for logout by monitoring cookie changes and update user.json if detected."""
    global driver, baseline_cookies
    if not driver:
        return False  # Return False if no logout detected
    
    try:
        current_cookies = {cookie['name']: cookie['value'] for cookie in driver.get_cookies()}
        key_cookie = 'session'  # Customize this based on your app's cookies (e.g., 'isAuthenticated')
        
        # Check if key cookie is missing or changed
        if key_cookie not in current_cookies or current_cookies.get(key_cookie) != baseline_cookies.get(key_cookie):
            logging.warning(f"Logout detected: {key_cookie} cookie changed or missing. Updating /var/www/html/assets/user.json...")
            
            # Update the file: Replace first "true" with "false"
            file_path = '/var/www/html/assets/users.json'
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                updated_content = content.replace('true', 'false', 1)
                
                with open(file_path, 'w') as f:
                    f.write(updated_content)
                
                logging.info(f"Updated {file_path}: Changed first 'true' to 'false'.")
                return True  # Logout detected and file updated
            except Exception as e:
                logging.error(f"Failed to update {file_path}: {e}")
                return False
        else:
            logging.debug("Login status unchanged.")
            return False
    except Exception as e:
        logging.error(f"Error during logout check: {e}")
        return False

class MailHandler(FileSystemEventHandler):
    def on_created(self, event):
        logging.debug(f"on_created triggered for: {event.src_path}")
        if not event.is_directory and '@mailhog.example' in event.src_path:
            logging.info(f"New mail detected: {event.src_path}")
            links = self.parse_mail_for_links(event.src_path)
            if links:
                for link_url in links:
                    logging.info(f"Extracted link: {link_url}")
                    self.visit_link(link_url)
            else:
                logging.info("No http:// links found in email.")
        else:
            logging.debug(f"Event ignored: is_directory={event.is_directory}, path={event.src_path}")

    def parse_mail_for_links(self, file_path):
        logging.debug(f"Parsing mail: {file_path}")
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            parts = content.split('\n\n', 1)
            if len(parts) < 2:
                return []
            body = parts[1]
            
            links = re.findall(r'http://[^\s]+', body)
            logging.debug(f"Found links: {links}")
            return links
        except Exception as e:
            logging.error(f"Error parsing mail: {e}")
            return []

    def visit_link(self, link_url):
        logging.debug(f"Visiting link: {link_url}")
        global driver
        if not driver:
            logging.error("Driver not initialized.")
            return
        
        try:
            driver.get(link_url)
            
            WebDriverWait(driver, 15).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Print cookies after visiting the link
            logging.info("Cookies after visiting link:")
            current_cookies = driver.get_cookies()
            for cookie in current_cookies:
                logging.info(str(cookie))
            
            if "login" in driver.current_url.lower():
                logging.warning(f"Visit failed for {link_url}: Redirected to login.")
            else:
                logging.info(f"Successfully visited {link_url}.")
            
            # Immediately check for logout after visiting the link
            check_logout_and_update_file()
        except Exception as e:
            logging.error(f"Error visiting {link_url}: {e}")

try:
    logging.debug("Starting script...")
    # Get the local IP address dynamically
    ip = get_ip_address()
    logging.info(f"Retrieved local IP address: {ip}")
    
    # Initialize driver and login once
    driver = webdriver.Chrome(service=service, options=options)
    driver.delete_all_cookies()
    logging.info("All Cookies Cleared.")
    logging.info("Driver initialized successfully.")

    # Navigate to login page using the dynamic IP
    login_url = f"http://{ip}/login"
    driver.get(login_url)
    logging.info(f"Navigated to login page: {login_url}")

    # Wait for email field
    wait = WebDriverWait(driver, 10)
    WebDriverWait(driver, 15).until(
        EC.presence_of_element_located((By.ID, "email"))
    )

    WebDriverWait(driver, 15).until(
        EC.presence_of_element_located((By.ID, "password"))
    )

    driver.execute_script("""
        function setReactInput(selector, value) {
        const input = document.querySelector(selector);
        const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype,
            "value"
        ).set;

        nativeInputValueSetter.call(input, value);

        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
        }

        setReactInput('#email', 'manav@mail.com');
        setReactInput('#password', 'attacker12345');
        """)

    # Click login
    login_button = wait.until(EC.element_to_be_clickable((By.ID, "login-button")))
    driver.execute_script("""
        document.querySelector('#loginForm')
        .dispatchEvent(new Event('submit', {
            bubbles: true,
            cancelable: true
        }));
        """)
    logging.info("Login button clicked.")

    # Handle any unexpected alerts before verification
    try:
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.accept()  # Dismiss the alert
        logging.warning(f"Dismissed alert after login: {alert_text}")
    except:
        logging.debug("No alert present after login.")

    # Verify login with fallback checks
    login_success = False
    try:
        wait.until(EC.visibility_of_element_located((By.XPATH, "//h2[text()='Admin Dashboard']")))
        is_authenticated = driver.execute_script("return window.localStorage.getItem('isAuthenticated');")
        logging.info(f"localStorage.isAuthenticated = {is_authenticated}")
        logging.info("Login successful via dashboard check!")
        login_success = True
    except TimeoutException:
        # Fallback: Check if redirected away from login page or for error messages
        if "login" not in driver.current_url.lower():
            logging.info("Login successful via URL check (redirected from login page).")
            login_success = True
        else:
            logging.error("Login failed: Still on login page or dashboard not found.")
    
    if not login_success:
        logging.error("Login failed. Page source snippet: " + driver.page_source[:500])
        driver.quit()
        exit(1)
    
    # Set baseline cookies after successful login
    baseline_cookies = {cookie['name']: cookie['value'] for cookie in driver.get_cookies()}
    logging.debug(f"Baseline cookies set: {list(baseline_cookies.keys())}")
    
    # Print cookies
    logging.info("Cookies after login:")
    cookies = driver.get_cookies()
    for cookie in cookies:
        logging.info(str(cookie))

    logging.debug("About to start monitoring...")
    # Start monitoring the mailhog volume path
    path = "/var/lib/docker/volumes/mailhog_data/_data"
    event_handler = MailHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    logging.info(f"Monitoring directory: {path}. Waiting for new emails...")

    # Keep running with constant cookie monitoring
    counter = 0
    while True:
        counter += 1
        # Check for logout every second
        if check_logout_and_update_file():
            logging.info("Logout detected and file updated. Continuing monitoring...")
        time.sleep(1)

except (NoSuchElementException, TimeoutException, UnexpectedAlertPresentException) as e:
    logging.error(f"Element interaction or alert error: {e}")
except Exception as e:
    logging.error(f"Unexpected error: {e}")
    traceback.print_exc()
finally:
    # Cleanup
    if observer:
        observer.stop()
        observer.join()
    if driver:
        driver.quit()
    logging.info("Script ended.")