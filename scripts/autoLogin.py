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
import threading
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
# Each incoming mail link is visited in its own tab; keep popups unblocked so
# tab/window creation is never silently dropped by headless Chrome.
options.add_argument("--disable-popup-blocking")

service = Service(executable_path='/opt/chromedriver-linux64/chromedriver')

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
driver           = None
observer         = None
baseline_sid     = None   # The exact connect.sid value captured after login
app_base_url     = None   # e.g. "http://192.168.34.18"  – our trusted origin
SCRIPT_EXITED    = False

# Selenium's WebDriver is NOT thread-safe: the mail-watcher thread visits
# attacker links while the main loop reads connect.sid. Every WebDriver call
# from either thread must hold this lock so the two threads never drive the
# browser at the same time.
driver_lock      = threading.Lock()

# Hard cap on how long we let a single attacker link load. The CSRF form
# auto-submits the instant its inline <script> runs, so a real attacker page
# fires well within this. A wrong/unreachable link can therefore waste at most
# this many seconds instead of hanging the watcher indefinitely.
LINK_VISIT_TIMEOUT = 8


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
# def get_sid_from_app():
#     """
#     Navigate the browser to the app's dashboard (our trusted origin) and
#     return the current value of connect.sid.

#     This is the ONLY safe way to read session cookies — reading them after
#     navigating to a third-party/error page gives an empty or unrelated jar.

#     Returns:
#         str   – the cookie value (may be empty string"" if absent)
#         None  – driver call failed entirely
#     """
#     global driver, app_base_url
#     try:
#         # Only navigate back if we are not already on the app domain
#         current = driver.current_url
#         #if not current.startswith(app_base_url):
#             #logging.debug(f"Browser is on '{current}', navigating back to app to read cookies.")
#         driver.get(f"{app_base_url}/login")
#         WebDriverWait(driver, 10).until(
#                 lambda d: d.execute_script("return document.readyState") == "complete"
#             )

#         cookies = driver.get_cookies()
#         for c in cookies:
#             if c['name'] == 'connect.sid':
#                 return c['value']
#         return ""   # cookie absent on the app domain

#     except Exception as e:
#         logging.error(f"get_sid_from_app() failed: {e}")
#         return None

def get_sid_from_app(force_reload=False):
    global driver, app_base_url
    try:
        current = driver.current_url
        
        # Navigate if forced (like during login), or if we are not on the app domain
        if force_reload or not current.startswith(app_base_url):
            driver.get(f"{app_base_url}/login")
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )

        cookies = driver.get_cookies()
        for c in cookies:
            if c['name'] == 'connect.sid':
                return c['value']
        return "" 

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

    current_sid = get_sid_from_app(force_reload=False)

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
# Login helpers
# ---------------------------------------------------------------------------
def submit_login_form():
    """
    Fill the React-controlled login inputs and submit the form.

    Assumes the browser is ALREADY on the /login page (the caller navigates
    there so it can read the pre-login cookie first). Dismisses any alert the
    page raises on failure. This function deliberately does NOT decide whether
    the login succeeded — that is the caller's job, via sid rotation +
    /api/adminMe validation.
    """
    global driver
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


def validate_admin_session():
    """
    Confirm the freshly-issued session is a genuine, authenticated ADMIN
    session by calling /api/adminMe from inside the browser.

    The request is same-origin (we are on the app domain), so the browser
    attaches connect.sid automatically — we are validating the EXACT cookie
    the app holds, not a value we copied around. /api/adminMe returns:
        200 -> valid session AND the user is an admin (what we want)
        401 -> no/invalid session, or not an admin
        403 -> no connect.sid cookie at all

    Returns True only on HTTP 200.
    """
    global driver
    try:
        # execute_async_script needs a generous script timeout for the fetch.
        driver.set_script_timeout(20)
        status = driver.execute_async_script("""
            const done = arguments[arguments.length - 1];
            fetch('/api/adminMe', { credentials: 'include' })
                .then(r => done(r.status))
                .catch(() => done(-1));
        """)
        logging.info(f"/api/adminMe validation returned HTTP {status}.")
        return status == 200
    except Exception as e:
        logging.error(f"validate_admin_session() failed: {e}")
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
        Visit the link extracted from an email in a SEPARATE FOREGROUND TAB,
        with a bounded load time, then close the tab.

        Why this shape:
        - PROMPT LOAD. The link is loaded in a tab we switch focus to, so Chrome
          does NOT throttle it the way it throttles background tabs. A single
          link therefore fires its CSRF POST immediately instead of crawling.
        - BOUNDED WASTE. A page-load timeout (LINK_VISIT_TIMEOUT) caps how long a
          wrong/unreachable link can take. The CSRF form auto-submits as soon as
          the attacker page's inline script runs, so a real page fires long
          before the cap; a bad link is abandoned after the cap instead of
          hanging forever.
        - SHARED SESSION. The tab shares the one cookie jar, so the attacker page
          auto-submits the CSRF with the admin connect.sid, and the server's
          clear-cookie (on /api/change-password) is visible to the monitor.
        - STABLE MONITORING. We always close the attacker tab and switch focus
          back to the main app tab, so the monitor keeps reading connect.sid
          against our trusted origin and is never dragged onto a third-party or
          error page.

        The driver_lock is held for the whole visit so this never races the
        monitor loop's cookie read. The monitoring loop (not this function) is
        solely responsible for detecting session changes and updating users.json.
        """
        global driver, driver_lock
        if not driver:
            logging.error("Driver not initialized.")
            return

        with driver_lock:
            main_handle = driver.current_window_handle
            new_handle = None
            try:
                # Open and focus a fresh tab so the page loads in the foreground.
                driver.switch_to.new_window('tab')
                new_handle = driver.current_window_handle

                # Cap the load; the CSRF POST fires well within this for a real
                # attacker page.
                driver.set_page_load_timeout(LINK_VISIT_TIMEOUT)
                try:
                    driver.get(link_url)
                    logging.info(f"Visited link (CSRF POST should have fired): {link_url}")
                except TimeoutException:
                    logging.warning(
                        f"Link did not finish loading within {LINK_VISIT_TIMEOUT}s "
                        f"(likely wrong/unreachable): {link_url}. Moving on."
                    )
                except WebDriverException as e:
                    # ERR_CONNECTION_REFUSED, ERR_NAME_NOT_RESOLVED, etc.
                    first_line = e.msg.splitlines()[0] if e.msg else str(e)
                    logging.warning(
                        f"Navigation error for {link_url}: {first_line}. Moving on."
                    )
            except Exception as e:
                logging.error(f"Failed to visit link {link_url}: {e}")
            finally:
                # Always tear down the attacker tab and return to the app tab.
                try:
                    if new_handle and new_handle in driver.window_handles:
                        driver.close()
                except Exception as e:
                    logging.error(f"Failed to close attacker tab: {e}")
                try:
                    driver.switch_to.window(main_handle)
                except Exception as e:
                    logging.error(f"Failed to switch back to main tab: {e}")
                # Restore a generous timeout for the monitor's own navigations.
                try:
                    driver.set_page_load_timeout(300)
                except Exception:
                    pass

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

    # ------------------------------------------------------------------
    # Login with retry.
    #
    # A successful login MUST rotate connect.sid: express-session issues a
    # brand-new session id once the credentials are accepted. So we:
    #   1. Navigate to /login and capture the PRE-login connect.sid.
    #   2. Submit the form.
    #   3. Capture the POST-login connect.sid.
    #   4. If the sid did NOT change, the login did not take effect (e.g. the
    #      backend was still warming up, or the credentials were rejected) —
    #      retry the whole flow.
    #   5. If the sid DID change, validate the new session by calling
    #      /api/adminMe with that exact cookie. Only HTTP 200 (authenticated
    #      admin) is accepted; anything else means the rotated sid is not a
    #      usable admin session, so we retry.
    #
    # This replaces the old "is the Admin Dashboard heading visible?" check,
    # which could pass while the underlying session was still invalid and
    # sometimes left us monitoring a bogus sid.
    # ------------------------------------------------------------------
    MAX_LOGIN_ATTEMPTS = 5
    baseline_sid = None

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        logging.info(f"Login attempt {attempt}/{MAX_LOGIN_ATTEMPTS}...")

        driver.get(login_url)
        logging.info(f"Navigated to: {login_url}")

        # Read the cookie BEFORE logging in. We are on the app domain
        # (/login), so get_sid_from_app() reads the real jar without
        # navigating away.
        pre_login_sid = get_sid_from_app(force_reload=True)
        logging.info(f"Pre-login connect.sid: {str(pre_login_sid)[:16]}...")

        submit_login_form()

        # Give express-session a moment to accept the credentials and
        # write the rotated cookie back to the browser.
        logging.info("Waiting 3 s for session cookie to rotate...")
        time.sleep(3)

        post_login_sid = get_sid_from_app(force_reload=True)
        logging.info(f"Post-login connect.sid: {str(post_login_sid)[:16]}...")

        if post_login_sid is None:
            logging.warning("Could not read connect.sid after login attempt; retrying.")
            continue

        if post_login_sid == pre_login_sid:
            logging.warning(
                "connect.sid did NOT change after login — login not effective; retrying."
            )
            continue

        # sid rotated -> validate the new session is a real admin session.
        if not validate_admin_session():
            logging.warning(
                "connect.sid rotated but /api/adminMe did not return 200; retrying."
            )
            continue

        if not post_login_sid:
            logging.warning("Rotated connect.sid is empty; retrying.")
            continue

        baseline_sid = post_login_sid
        logging.info("Login confirmed: sid rotated and /api/adminMe returned 200.")
        break

    if not baseline_sid:
        logging.error(
            f"Login failed after {MAX_LOGIN_ATTEMPTS} attempts "
            "(no valid rotated admin session). Exiting."
        )
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
        # The watcher thread may be opening attacker tabs concurrently. Hold
        # the lock for the cookie read so we never read connect.sid while a
        # WebDriver command from the watcher is in flight.
        with driver_lock:
            session_terminated = check_session_and_update_file()

        if session_terminated:
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
