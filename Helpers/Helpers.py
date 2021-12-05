from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import IEDriverManager
from selenium.webdriver.ie.options import Options as IEoptions


def webdriver_chrome():
    chrome_options = Options()
    chrome_options.add_argument('--ignore-certificate-errors')
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)
    return driver


# Need a custom profile for the scan via URL test so that it automatically opens the scan agent app in Chrome
def webdriver_chrome_scans():
    chrome_options = Options()
    chrome_options.add_argument(r'user-data-dir=C:\Users\nable\AppData\Local\Google\Chrome\User Data')
    chrome_options.add_argument('--profile-directory=Profile 1')
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)
    return driver


def webdriver_firefox():
    options = webdriver.FirefoxOptions()
    options.set_preference("dom.webnotifications.enabled", False)
    options.set_preference("browser.download.folderList", 2)
    options.set_preference("browser.download.dir", r"C:\Jenkins\temp")
    options.set_preference("browser.helperApps.neverAsk.saveToDisk", "application/octet-stream")
    driver = webdriver.Firefox(executable_path=GeckoDriverManager().install(), options=options)
    return driver


def webdriver_ie():
    ie_options = IEoptions()
    ie_options.ignore_zoom_level = True
    ie_options.require_window_focus = True
    ie_options.full_page_screenshot = True
    ie_options.ensure_clean_session = True
    ie_options.ignore_protected_mode_settings = True
    driver = webdriver.Ie(IEDriverManager().install(), options=ie_options)
    return driver
