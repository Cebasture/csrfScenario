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
import urllib.request
import urllib.error

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

service = Service(executable_path='/opt/chromedriver-linux64/chromedriver')

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
# Readiness probe
# ---------------------------------------------------------------------------
def wait_for_app_ready(base_url, timeout=180, interval=3):
    """
    Poll the frontend (apache) AND the backend API until both respond, so we
    never attempt to log in before the whole stack is actually serving.

    This replaces the old blind 'sleep 10' in the systemd unit, which was too
    short on a cold boot and let selenium log into a backend that then
    restarted (wiping the in-memory session) — the cause of the first-boot
    CSRF failure.

    Any HTTP status counts as "up": e.g. /api/csrf-token returns 401 with no
    session, which still proves the API is listening. Only connection errors
    and timeouts are treated as not-ready.

    Returns True once both endpoints respond, False if the timeout is hit
    (in which case we proceed anyway and let the normal login flow retry).
    """
    endpoints = [f"{base_url}/login", f"{base_url}/api/csrf-token"]
    deadline = time.time() + timeout
    pending = list(endpoints)

    while pending:
        still_pending = []
        for url in pending:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    logging.info(f"Readiness: {url} responded HTTP {resp.status} (up).")
            except urllib.error.HTTPError as e:
                # An HTTP error is still a response -> the server is up.
                logging.info(f"Readiness: {url} responded HTTP {e.code} (up).")
            except Exception as e:
                logging.debug(f"Readiness: {url} not ready yet: {e}")
                still_pending.append(url)

        pending = still_pending
        if not pending:
            logging.info("Readiness: app is up (frontend + API responding).")
            return True

        if time.time() >= deadline:
            logging.warning(
                f"Readiness: timed out after {timeout}s; still not ready: {pending}. "
                "Proceeding anyway."
            )
            return False

        time.sleep(interval)

    return True


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
    # Wait for the full stack (apache frontend + node API) to be ready
    # before doing anything, instead of relying on a fixed boot delay.
    # ------------------------------------------------------------------
    wait_for_app_ready(app_base_url)

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
