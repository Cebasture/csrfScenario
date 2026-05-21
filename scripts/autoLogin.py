# from selenium import webdriver
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.chrome.service import Service
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from selenium.common.exceptions import NoSuchElementException, TimeoutException, UnexpectedAlertPresentException
# from watchdog.observers import Observer
# from watchdog.events import FileSystemEventHandler
# import time
# import subprocess
# import traceback
# import re
# import logging
# import json  # For potential JSON validation (optional)
# import socket
# import sys
# # Set up logging to file
# logging.basicConfig(
#     filename='/home/john/autoLogin.log',
#     level=logging.DEBUG,
#     format='%(asctime)s - %(levelname)s - %(message)s',
#     filemode='a'
# )

# # # Set up logging to file

# console = logging.StreamHandler()
# console.setLevel(logging.INFO)
# formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# console.setFormatter(formatter)
# logging.getLogger('').addHandler(console)

# # Set up headless Chrome
# options = Options()
# options.add_argument("--headless=new")
# options.add_argument("--no-sandbox")
# options.add_argument("--disable-dev-shm-usage")

# # Service setup
# service = Service(executable_path='/home/john/drivers/chromedriver-linux64/chromedriver')

# # Global variables
# driver = None
# observer = None
# baseline_cookies = {}

# # def get_ip_address():
# #     """Retrieve the local IP address by connecting to an external host."""
# #     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# #     try:
# #         s.connect(("8.8.8.8", 80))
# #         ip = s.getsockname()[0]
# #         return ip
# #     except Exception as e:
# #         logging.error(f"Failed to get local IP: {e}")
# #         raise
# #     finally:
# #         s.close()

# def get_enp0s8_ip():
#     global enp0s8_ip
#     try:
#         result = subprocess.run(['ip', 'addr', 'show', 'enp0s8'], capture_output=True, text=True)
#         match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/', result.stdout)
#         if match:
#             enp0s8_ip = match.group(1)
#             logging.info(f"enp0s8 IP: {enp0s8_ip}")
#             return enp0s8_ip
#     except:
#         pass
    
#     logging.warning("enp0s8 not found, trying enp0s8...")
#     try:
#         result = subprocess.run(['ip', 'addr', 'show', 'enp0s8'], capture_output=True, text=True)
#         match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/', result.stdout)
#         if match:
#             enp0s8_ip = match.group(1)
#             logging.info(f"enp0s8 IP: {enp0s8_ip}")
#             return enp0s8_ip
#     except:
#         pass
#     return None

# def check_logout_and_update_file():
#     """Check for logout by monitoring cookie changes and update user.json if detected."""
#     global driver, baseline_cookies
#     if not driver:
#         return False  # Return False if no logout detected
    
#     try:
#         current_cookies = {cookie['name']: cookie['value'] for cookie in driver.get_cookies()}
#         key_cookie = 'connect.sid'  # Customize this based on your app's cookies (e.g., 'isAuthenticated')
        
#         # Check if key cookie is missing or changed
#         if key_cookie not in current_cookies or current_cookies.get(key_cookie) != baseline_cookies.get(key_cookie):
#             logging.warning(f"Logout detected: {key_cookie} cookie changed or missing. Updating /var/www/html/assets/user.json...")
            
#             # Update the file: Replace first "true" with "false"
#             file_path = '/var/www/html/assets/users.json'
#             try:
#                 with open(file_path, 'r') as f:
#                     content = f.read()
                
#                 updated_content = content.replace('true', 'false', 1)
                
#                 with open(file_path, 'w') as f:
#                     f.write(updated_content)
                
#                 logging.info(f"Updated {file_path}: Changed first 'true' to 'false'.")
#                 cleanup_and_exit()
#                 return True  # Logout detected and file updated
#             except Exception as e:
#                 logging.error(f"Failed to update {file_path}: {e}")
#                 return False
#         else:
#             logging.debug("Login status unchanged.")
#             return False
#     except Exception as e:
#         logging.error(f"Error during logout check: {e}")
#         return False

# def cleanup_and_exit():
#     """Graceful cleanup and TERMINATE script."""
#     global observer, driver, SCRIPT_EXITED
    
#     if SCRIPT_EXITED:
#         return
    
#     SCRIPT_EXITED = True
#     logging.info("TERMINATING SCRIPT - Final cleanup...")
    
#     try:
#         if observer:
#             logging.info("Stopping observer...")
#             observer.stop()
#             observer.join(timeout=3)
        
#         if driver:
#             logging.info("Closing driver...")
#             driver.delete_all_cookies()
#             driver.quit()
        
#         logging.info("SCRIPT COMPLETELY TERMINATED")
#         sys.exit(0)
        
#     except Exception as e:
#         logging.error(f"Cleanup error: {e}")
#         sys.exit(1)

# class MailHandler(FileSystemEventHandler):
#     def on_created(self, event):
#         logging.debug(f"on_created triggered for: {event.src_path}")
#         if not event.is_directory and '.NewtBug' in event.src_path:
#             logging.info(f"New mail detected: {event.src_path}")
#             links = self.parse_mail_for_links(event.src_path)
#             if links:
#                 for link_url in links:
#                     logging.info(f"Extracted link: {link_url}")
#                     self.visit_link(link_url)
#             else:
#                 logging.info("No http:// links found in email.")
#         else:
#             logging.debug(f"Event ignored: is_directory={event.is_directory}, path={event.src_path}")

#     def parse_mail_for_links(self, file_path):
#         logging.debug(f"Parsing mail: {file_path}")
#         try:
#             with open(file_path, 'r') as f:
#                 content = f.read()
            
#             parts = content.split('\n\n', 1)
#             if len(parts) < 2:
#                 return []
#             body = parts[1]
            
#             links = re.findall(r'http://[^\s]+', body)
#             logging.debug(f"Found links: {links}")
#             return links
#         except Exception as e:
#             logging.error(f"Error parsing mail: {e}")
#             return []

#     def visit_link(self, link_url):
#         logging.debug(f"Visiting link: {link_url}")
#         global driver
#         if not driver:
#             logging.error("Driver not initialized.")
#             return
        
#         time.sleep(10)  # Brief pause before visiting link
        
#         try:
#             driver.get(link_url)
            
#             WebDriverWait(driver, 15).until(
#                 lambda d: d.execute_script("return document.readyState") == "complete"
#             )
#             WebDriverWait(driver, 15).until(
#                 EC.presence_of_element_located((By.TAG_NAME, "body"))
#             )
            
#             # Print cookies after visiting the link
#             logging.info("Cookies after visiting link:")
#             current_cookies = driver.get_cookies()
#             for cookie in current_cookies:
#                 logging.info(str(cookie))
            
#             if "login" in driver.current_url.lower():
#                 logging.warning(f"Visit failed for {link_url}: Redirected to login.")
#             else:
#                 logging.info(f"Successfully visited {link_url}.")
            
#             # Immediately check for logout after visiting the link
#             check_logout_and_update_file()
#         except Exception as e:
#             logging.error(f"Error visiting {link_url}: {e}")

# try:
#     logging.debug("Starting script...")
#     # Get the local IP address dynamically
#     ip = get_enp0s8_ip()
#     logging.info(f"Retrieved local IP address: {ip}")
    
#     # Initialize driver and login once
#     driver = webdriver.Chrome(service=service, options=options)
#     driver.delete_all_cookies()
#     logging.info("All Cookies Cleared.")
#     logging.info("Driver initialized successfully.")

#     # Navigate to login page using the dynamic IP
#     login_url = f"http://{ip}/login"
#     driver.get(login_url)
#     logging.info(f"Navigated to login page: {login_url}")

#     # Wait for email field
#     wait = WebDriverWait(driver, 10)
#     WebDriverWait(driver, 15).until(
#         EC.presence_of_element_located((By.ID, "email"))
#     )

#     WebDriverWait(driver, 15).until(
#         EC.presence_of_element_located((By.ID, "password"))
#     )

#     driver.execute_script("""
#         function setReactInput(selector, value) {
#         const input = document.querySelector(selector);
#         const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
#             window.HTMLInputElement.prototype,
#             "value"
#         ).set;

#         nativeInputValueSetter.call(input, value);

#         input.dispatchEvent(new Event('input', { bubbles: true }));
#         input.dispatchEvent(new Event('change', { bubbles: true }));
#         }

#         setReactInput('#email', 'john@newtbug.com');
#         setReactInput('#password', 'Z8ctUXdmoIxsgG0wqMWU');
#         """)

#     # Click login
#     login_button = wait.until(EC.element_to_be_clickable((By.ID, "login-button")))
#     driver.execute_script("""
#         document.querySelector('#loginForm')
#         .dispatchEvent(new Event('submit', {
#             bubbles: true,
#             cancelable: true
#         }));
#         """)
#     logging.info("Login button clicked.")

#     # Handle any unexpected alerts before verification
#     try:
#         alert = driver.switch_to.alert
#         alert_text = alert.text
#         alert.accept()  # Dismiss the alert
#         logging.warning(f"Dismissed alert after login: {alert_text}")
#     except:
#         logging.debug("No alert present after login.")

#     # Verify login with fallback checks
#     login_success = False
#     try:
#         wait.until(EC.visibility_of_element_located((By.XPATH, "//h2[text()='Admin Dashboard']")))
#         is_authenticated = driver.execute_script("return window.localStorage.getItem('isAuthenticated');")
#         logging.info(f"localStorage.isAuthenticated = {is_authenticated}")
#         logging.info("Login successful via dashboard check!")
#         login_success = True
#     except TimeoutException:
#         # Fallback: Check if redirected away from login page or for error messages
#         if "login" not in driver.current_url.lower():
#             logging.info("Login successful via URL check (redirected from login page).")
#             login_success = True
#         else:
#             logging.error("Login failed: Still on login page or dashboard not found.")
    
#     if not login_success:
#         logging.error("Login failed. Page source snippet: " + driver.page_source[:500])
#         driver.quit()
#         exit(1)
    
#     # Set baseline cookies after successful login
#     baseline_cookies = {cookie['name']: cookie['value'] for cookie in driver.get_cookies()}
#     logging.debug(f"Baseline cookies set: {list(baseline_cookies.keys())}")
    
#     # Print cookies
#     logging.info("Cookies after login:")
#     cookies = driver.get_cookies()
#     for cookie in cookies:
#         logging.info(str(cookie))

#     logging.debug("About to start monitoring...")
#     # Start monitoring the mailhog volume path
#     path = "/home/john/Maildir/new"
#     event_handler = MailHandler()
#     observer = Observer()
#     observer.schedule(event_handler, path, recursive=False)
#     observer.start()
#     logging.info(f"Monitoring directory: {path}. Waiting for new emails...")# Call once to log initial state


#     # Keep running with constant cookie monitoring
#     counter = 0
#     while True:
#         counter += 1
#         # Check for logout every second
#         if check_logout_and_update_file():
#             logging.info("Logout detected and file updated. Continuing monitoring...")
#         time.sleep(1)

# except (NoSuchElementException, TimeoutException, UnexpectedAlertPresentException) as e:
#     logging.error(f"Element interaction or alert error: {e}")
# except Exception as e:
#     logging.error(f"Unexpected error: {e}")
#     traceback.print_exc()
# finally:
#     # Cleanup
#     if observer:
#         observer.stop()
#         observer.join()
#     if driver:
#         driver.quit()
#     logging.info("Script ended.")
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    NoSuchElementException, TimeoutException, UnexpectedAlertPresentException,
    WebDriverException
)
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import subprocess
import traceback
import re
import logging
import sys

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename='/home/john/autoLogin.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger('').addHandler(console)

# ---------------------------------------------------------------------------
# Chrome setup
# ---------------------------------------------------------------------------
options = Options()
options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")

service = Service(executable_path='/home/john/drivers/chromedriver-linux64/chromedriver')

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
driver           = None
observer         = None
baseline_sid     = None   # The exact connect.sid value captured after login
app_base_url     = None   # e.g. "http://192.168.34.18"  – our trusted origin
SCRIPT_EXITED    = False


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def get_non_loopback_ip():
    """
    Return the IPv4 address of the single non-loopback interface.
    Reads /proc/net/dev for interface names, skips 'lo', then uses
    'ip addr show <iface>' to extract the address.
    Works regardless of the interface name (enp0s3, eth0, ens33, etc.)
    """
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()

        interfaces = []
        for line in lines:
            line = line.strip()
            if ':' in line:
                iface = line.split(':')[0].strip()
                if iface != 'lo':
                    interfaces.append(iface)

        if not interfaces:
            logging.error("No non-loopback interfaces found in /proc/net/dev.")
            return None

        if len(interfaces) > 1:
            logging.warning(f"Multiple non-loopback interfaces found: {interfaces}. Using: {interfaces[0]}")

        iface = interfaces[0]
        logging.info(f"Non-loopback interface: {iface}")

        result = subprocess.run(['ip', 'addr', 'show', iface],
                                capture_output=True, text=True)
        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/', result.stdout)
        if match:
            ip = match.group(1)
            logging.info(f"{iface} IP: {ip}")
            return ip

        logging.error(f"Could not parse IP from 'ip addr show {iface}' output.")
        return None

    except Exception as e:
        logging.error(f"Error detecting non-loopback IP: {e}")
        return None


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------
def get_sid_from_app():
    """
    Navigate the browser to the app's dashboard (our trusted origin) and
    return the current value of connect.sid.

    This is the ONLY safe way to read session cookies — reading them after
    navigating to a third-party/error page gives an empty or unrelated jar.

    Returns:
        str   – the cookie value (may be empty string "" if absent)
        None  – driver call failed entirely
    """
    global driver, app_base_url
    try:
        # Only navigate back if we are not already on the app domain
        current = driver.current_url
        if not current.startswith(app_base_url):
            logging.debug(f"Browser is on '{current}', navigating back to app to read cookies.")
            driver.get(f"{app_base_url}/")
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )

        cookies = driver.get_cookies()
        for c in cookies:
            if c['name'] == 'connect.sid':
                return c['value']
        return ""   # cookie absent on the app domain

    except Exception as e:
        logging.error(f"get_sid_from_app() failed: {e}")
        return None


def check_session_and_update_file():
    """
    Check whether the server has destroyed the admin session by comparing
    the current connect.sid (read from the app domain) to the baseline.

    A change is only meaningful when:
      1. The browser is on OUR app domain (not an error page or third-party page).
      2. The cookie is genuinely gone or its value has changed.

    Returns True  -> session terminated, users.json updated -> caller must exit.
    Returns False -> session intact or read failed -> keep monitoring.
    """
    global baseline_sid

    current_sid = get_sid_from_app()

    if current_sid is None:
        # Driver error - skip this tick, do not act
        logging.debug("Skipping session check: could not read cookies from app.")
        return False

    # Cookie unchanged
    if current_sid == baseline_sid:
        logging.debug(f"connect.sid unchanged ({current_sid[:16]}...) - session active.")
        return False

    # Cookie absent or rotated -> session was destroyed by the server
    if current_sid == "":
        logging.warning("connect.sid is GONE on app domain - session destroyed by server (CSRF confirmed).")
    else:
        logging.warning(
            f"connect.sid CHANGED: {baseline_sid[:16]}... -> {current_sid[:16]}... "
            "- server issued new session (old one destroyed)."
        )

    # Update users.json
    file_path = '/var/www/html/assets/users.json'
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        updated_content = content.replace('true', 'false', 1)

        with open(file_path, 'w') as f:
            f.write(updated_content)

        logging.info(f"Updated {file_path}: first 'true' -> 'false'.")
        return True

    except Exception as e:
        logging.error(f"Failed to update {file_path}: {e}")
        return False


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
def cleanup_and_exit():
    global observer, driver, SCRIPT_EXITED

    if SCRIPT_EXITED:
        return
    SCRIPT_EXITED = True

    logging.info("TERMINATING SCRIPT - final cleanup...")
    try:
        if observer:
            logging.info("Stopping observer...")
            observer.stop()
            observer.join(timeout=3)
        if driver:
            logging.info("Closing driver...")
            driver.delete_all_cookies()
            driver.quit()
        logging.info("SCRIPT COMPLETELY TERMINATED.")
    except Exception as e:
        logging.error(f"Cleanup error: {e}")
    finally:
        sys.exit(0)


# ---------------------------------------------------------------------------
# Mail watcher
# ---------------------------------------------------------------------------
class MailHandler(FileSystemEventHandler):

    def on_created(self, event):
        logging.debug(f"on_created triggered: {event.src_path}")
        if not event.is_directory and '.NewtBug' in event.src_path:
            logging.info(f"New mail detected: {event.src_path}")
            links = self.parse_mail_for_links(event.src_path)
            if links:
                for link_url in links:
                    logging.info(f"Extracted link: {link_url}")
                    self.visit_link(link_url)
            else:
                logging.info("No http:// links found in email.")
        else:
            logging.debug(f"Ignored: is_directory={event.is_directory}, path={event.src_path}")

    def parse_mail_for_links(self, file_path):
        logging.debug(f"Parsing mail: {file_path}")
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            parts = content.split('\n\n', 1)
            if len(parts) < 2:
                return []
            links = re.findall(r'http://[^\s]+', parts[1])
            logging.debug(f"Found links: {links}")
            return links
        except Exception as e:
            logging.error(f"Error parsing mail: {e}")
            return []

    def visit_link(self, link_url):
        """
        Navigate to the link extracted from the email.

        Critical guarantees:
        - If the navigation fails for ANY reason (timeout, connection refused,
          DNS error, etc.) we navigate back to the app and do NOT treat the
          failure as a session change.
        - We never inspect cookies while on a third-party or error page.
        - The monitoring loop (not this function) is solely responsible for
          detecting session changes.
        """
        global driver, app_base_url
        if not driver:
            logging.error("Driver not initialized.")
            return

        sid_before = get_sid_from_app()
        logging.info(f"connect.sid before visiting link: {str(sid_before)[:16]}...")

        logging.info(f"Visiting link: {link_url}")
        time.sleep(5)  # Brief settle before navigation

        navigation_succeeded = False
        try:
            driver.get(link_url)

            WebDriverWait(driver, 15).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            navigation_succeeded = True
            logging.info(f"Successfully loaded: {link_url} (current URL: {driver.current_url})")

        except TimeoutException:
            logging.warning(
                f"Timeout loading {link_url}. "
                "Navigation incomplete - will return to app and continue monitoring."
            )
        except WebDriverException as e:
            # Covers ERR_CONNECTION_REFUSED, ERR_NAME_NOT_RESOLVED, etc.
            logging.warning(
                f"Navigation error for {link_url}: {e.msg.splitlines()[0]}. "
                "Will return to app and continue monitoring."
            )
        except Exception as e:
            logging.error(f"Unexpected error visiting {link_url}: {e}")

        finally:
            # ----------------------------------------------------------
            # ALWAYS navigate back to the app domain after visiting any
            # external link (successful or not), so that subsequent
            # cookie reads are against our trusted origin and not an
            # error page or third-party page with an empty cookie jar.
            # ----------------------------------------------------------
            if not navigation_succeeded or not driver.current_url.startswith(app_base_url):
                try:
                    logging.debug("Returning browser to app domain after link visit...")
                    driver.get(f"{app_base_url}/")
                    WebDriverWait(driver, 10).until(
                        lambda d: d.execute_script("return document.readyState") == "complete"
                    )
                except Exception as e:
                    logging.error(f"Could not navigate back to app: {e}")

            sid_after = get_sid_from_app()
            logging.info(
                f"connect.sid after link visit: {str(sid_after)[:16]}... "
                f"({'CHANGED' if sid_after != sid_before else 'unchanged'})"
            )

        # Monitoring loop handles all decisions — we never update users.json here.


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try:
    logging.debug("Starting script...")

    ip = get_non_loopback_ip()
    if not ip:
        logging.error("Could not determine IP address. Exiting.")
        sys.exit(1)

    app_base_url = f"http://{ip}"
    logging.info(f"App base URL: {app_base_url}")

    # ------------------------------------------------------------------
    # Browser init + login
    # ------------------------------------------------------------------
    driver = webdriver.Chrome(service=service, options=options)
    driver.delete_all_cookies()
    logging.info("All cookies cleared. Driver initialised.")

    login_url = f"{app_base_url}/login"
    driver.get(login_url)
    logging.info(f"Navigated to: {login_url}")

    wait = WebDriverWait(driver, 15)
    wait.until(EC.presence_of_element_located((By.ID, "email")))
    wait.until(EC.presence_of_element_located((By.ID, "password")))

    driver.execute_script("""
        function setReactInput(selector, value) {
            const input = document.querySelector(selector);
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, "value"
            ).set;
            nativeInputValueSetter.call(input, value);
            input.dispatchEvent(new Event('input',  { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
        }
        setReactInput('#email',    'john@newtbug.com');
        setReactInput('#password', 'Z8ctUXdmoIxsgG0wqMWU');
    """)

    wait.until(EC.element_to_be_clickable((By.ID, "login-button")))
    driver.execute_script("""
        document.querySelector('#loginForm')
            .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    """)
    logging.info("Login form submitted.")

    try:
        alert = driver.switch_to.alert
        logging.warning(f"Dismissed alert after login: {alert.text}")
        alert.accept()
    except Exception:
        logging.debug("No alert present after login.")

    # Verify login
    login_success = False
    try:
        wait.until(EC.visibility_of_element_located((By.XPATH, "//h2[text()='Admin Dashboard']")))
        is_auth = driver.execute_script("return window.localStorage.getItem('isAuthenticated');")
        logging.info(f"localStorage.isAuthenticated = {is_auth}")
        logging.info("Login successful via dashboard check!")
        login_success = True
    except TimeoutException:
        if "login" not in driver.current_url.lower():
            logging.info("Login successful via URL check.")
            login_success = True
        else:
            logging.error("Login failed: still on login page.")

    if not login_success:
        logging.error("Login failed. Page source:\n" + driver.page_source[:500])
        driver.quit()
        sys.exit(1)

    # ------------------------------------------------------------------
    # Wait briefly for express-session to persist, then capture baseline.
    # The baseline is always read from the app domain (we're on it now).
    # ------------------------------------------------------------------
    logging.info("Waiting 3 s for session cookie to stabilise...")
    time.sleep(3)

    baseline_sid = get_sid_from_app()
    if not baseline_sid:
        logging.error("connect.sid not found after login. Cannot monitor session. Exiting.")
        driver.quit()
        sys.exit(1)

    logging.info(f"Baseline connect.sid captured: {baseline_sid}")
    logging.info("Full cookie jar after login:")
    for cookie in driver.get_cookies():
        logging.info(str(cookie))

    # ------------------------------------------------------------------
    # Start Maildir watcher
    # ------------------------------------------------------------------
    path = "/home/john/Maildir/new"
    event_handler = MailHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    logging.info(f"Monitoring {path}. Waiting for new emails...")

    # ------------------------------------------------------------------
    # Main polling loop
    #
    # ONLY exits when connect.sid has genuinely changed/disappeared as
    # read from the app domain. Navigation failures, timeouts, or errors
    # on third-party pages do NOT trigger termination.
    # ------------------------------------------------------------------
    while True:
        if check_session_and_update_file():
            logging.info(
                "Session invalidation confirmed and users.json updated. "
                "Initiating graceful shutdown..."
            )
            cleanup_and_exit()  # does not return

        time.sleep(1)

except (NoSuchElementException, TimeoutException, UnexpectedAlertPresentException) as e:
    logging.error(f"Element/alert error: {e}")
except Exception as e:
    logging.error(f"Unexpected error: {e}")
    traceback.print_exc()
finally:
    if not SCRIPT_EXITED:
        if observer:
            observer.stop()
            observer.join()
        if driver:
            driver.quit()
    logging.info("Script ended.")