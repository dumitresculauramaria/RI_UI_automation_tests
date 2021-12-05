import time
import unittest
import os
from glob import glob
from os import getenv

import dotenv
import requests
import xmlrunner
import selenium
from selenium.common.exceptions import TimeoutException, ElementClickInterceptedException, UnexpectedAlertPresentException
from selenium.webdriver import ActionChains
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.select import Select
from selenium.webdriver.support.ui import WebDriverWait
from Helpers.Helpers import webdriver_chrome, webdriver_firefox, webdriver_ie
import Helpers.Logger
from testrail_api import TestRailAPI


def ui_tests(env, path, wbdrv):
    global logger
    logger = Helpers.Logger.logger()
    dotenv.load_dotenv(verbose=True)
    global short_code
    if env == getenv('RI_STAGE'):
        short_code = getenv('STAGE_SCAN_CODE')
    elif env == getenv('RI_STAGE_EMEA'):
        short_code = getenv('TEST_SCAN_CODE')
    elif env == getenv('RI_TEST'):
        short_code = getenv('TEST_SCAN_CODE')
    elif env == getenv('RI_PROD'):
        short_code = getenv('PROD_SCAN_CODE')
    elif env == getenv('RI_PROD_EMEA'):
        short_code = getenv('PROD_EMEA_SCAN_CODE')

    # Define widely used methods here for ease of use in tests
    def login():
        try:
            WebDriverWait(driver, 180).until(EC.title_contains('Enter your login'))
        except TimeoutException:
            logger.critical('Page timed out, app may be offline - aborting test')
            driver.save_screenshot(path + 'login_page_timeout.png')
            raise Exception('Page timed out - aborting test')
        try:
            email = WebDriverWait(driver, 30).until(
                EC.visibility_of_element_located((By.ID, 'email-field')))
            if env == getenv('RI_PROD') or env == getenv('RI_PROD_EMEA') or env == getenv('RI_PROD_INTEGRATED'):
                email.send_keys(getenv('RI_PROD_USER'))
            if env == getenv('RI_TEST') or env == getenv('RI_STAGE') or env == getenv('RI_STAGE_EMEA'):
                email.send_keys(getenv('RI_USER'))
            if env == getenv('RI_STAGE_INTEGRATED'):
                email.send_keys(getenv('RI_STAGE_INTEGRATED_USER'))
            password = WebDriverWait(driver, 30).until(
                EC.visibility_of_element_located((By.ID, 'password-field')))
            password.send_keys(os.getenv('RI_PASS'))
            WebDriverWait(driver, 20).until(
                EC.visibility_of_element_located((By.ID, 'password-submit'))).click()
            try:
                WebDriverWait(driver, 60).until(
                    EC.visibility_of_element_located((By.ID, 'dashboard')))
            except TimeoutException:
                driver.refresh()
                time.sleep(3)
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Retry login')]"))).click()
                    time.sleep(3)
                except TimeoutException:
                    driver.refresh()
                    email = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'email-field')))
                    if env == getenv('RI_PROD') or env == getenv('RI_PROD_EMEA') or env == getenv('RI_PROD_INTEGRATED'):
                        email.send_keys(getenv('RI_PROD_USER'))
                    if env == getenv('RI_TEST') or env == getenv('RI_STAGE') or env == getenv('RI_STAGE_EMEA'):
                        email.send_keys(getenv('RI_USER'))
                    if env == getenv('RI_STAGE_INTEGRATED'):
                        email.send_keys(getenv('RI_STAGE_INTEGRATED_USER'))
                    password = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'password-field')))
                    password.send_keys(os.getenv('RI_PASS'))
                    WebDriverWait(driver, 20).until(
                        EC.visibility_of_element_located((By.ID, 'password-submit'))).click()
                WebDriverWait(driver, 60).until(
                    EC.visibility_of_element_located((By.ID, 'dashboard')))
        except TimeoutException:
            logger.critical('There was an issue login in - please check the screenshot!')
            driver.save_screenshot(path + 'login_issue.png')
            raise Exception('Could not log in - aborting test')

    def change_context():
        if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'context-btn'))).click()
                time.sleep(5)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Current VAR:')]"))).click()
                time.sleep(3)
                field = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, "user_context_domain")))
                field.click()
                time.sleep(3)
                field.send_keys('Customer Conference')
                driver.save_screenshot(path + 'change_context_popup.png')
                time.sleep(5)
                actions = ActionChains(driver)
                if env == getenv('RI_PROD_INTEGRATED'):
                    actions.send_keys(Keys.ARROW_DOWN)
                    time.sleep(1)
                    actions.send_keys(Keys.ARROW_DOWN)
                    time.sleep(1)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.ENTER)
                else:
                    actions.send_keys(Keys.ARROW_DOWN)
                    time.sleep(1)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.ENTER)
                actions.perform()
                time.sleep(5)
                WebDriverWait(driver, 10).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Customer Conference')]")))
            except TimeoutException:
                # Sometimes it doesn't work on the first try
                try:
                    WebDriverWait(driver, 10).until(
                        EC.visibility_of_element_located((By.ID, 'context-btn'))).click()
                    time.sleep(5)
                    WebDriverWait(driver, 20).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Current VAR:')]"))).click()
                    time.sleep(3)
                    field = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, "user_context_domain")))
                    field.click()
                    time.sleep(3)
                    field.send_keys('Customer Conference')
                    driver.save_screenshot(path + 'change_context_popup.png')
                    time.sleep(5)
                    actions = ActionChains(driver)
                    if env == getenv('RI_PROD_INTEGRATED'):
                        actions.send_keys(Keys.ARROW_DOWN)
                        time.sleep(1)
                        actions.send_keys(Keys.ARROW_DOWN)
                        time.sleep(1)
                        actions.send_keys(Keys.ENTER)
                        time.sleep(1)
                        actions.send_keys(Keys.ENTER)
                    else:
                        actions.send_keys(Keys.ARROW_DOWN)
                        time.sleep(1)
                        actions.send_keys(Keys.ENTER)
                        time.sleep(1)
                        actions.send_keys(Keys.ENTER)
                    actions.perform()
                    time.sleep(5)
                    WebDriverWait(driver, 10).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Customer Conference')]")))
                except TimeoutException:
                    logger.critical('There was an issue changing the context - please check the screenshot!')
                    driver.save_screenshot(path + 'change_context_issue.png')
                    raise Exception
        else:
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'context-btn'))).click()
                field = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, "user_context_domain")))
                field.click()
                field.send_keys('Stark Enterprises')
                driver.save_screenshot(path + 'change_context_popup.png')
                organization_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'user_context_organization')))
                organization_name.click()
                organization_name.send_keys('Stark Enterprises')
                actions = ActionChains(driver)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                time.sleep(3)
                WebDriverWait(driver, 10).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Stark Enterprises')]")))
            # Sometimes it doesn't work on the first try so we can try again
            except TimeoutException:
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'context-btn'))).click()
                    field = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, "user_context_domain")))
                    field.click()
                    field.send_keys('Stark Enterprises')
                    driver.save_screenshot(path + 'change_context_popup.png')
                    organization_name = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'user_context_organization')))
                    organization_name.click()
                    organization_name.send_keys('Stark Enterprises')
                    actions = ActionChains(driver)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                    time.sleep(3)
                    WebDriverWait(driver, 10).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Stark Enterprises')]")))
                except TimeoutException:
                    logger.critical('There was an issue changing the context - please check the screenshot!')
                    driver.save_screenshot(path + 'change_context_issue.png')
                    raise Exception

    class Basic_Checks(unittest.TestCase):
        def setUp(self, webdriver=wbdrv):
            if webdriver == 'chrome':
                webdriver = webdriver_chrome()
            if webdriver == 'firefox':
                webdriver = webdriver_firefox()
            if webdriver == 'ie':
                webdriver = webdriver_ie()
            global driver
            driver = webdriver
            logger.debug('Starting the test case using ' + str(driver.name) + ' on the following env.: ' + str(env))
            driver.get(env)
            driver.maximize_window()

        # Login basic checks
        @staticmethod
        def test_login_checks():
            logger.debug('UI test - Basic login checks')
            try:
                WebDriverWait(driver, 180).until(EC.title_contains('Enter your login'))
                driver.save_screenshot(path + 'login_page.png')
            except TimeoutException:
                logger.critical('Page timed out, app may be offline - aborting test')
                driver.save_screenshot(path + 'login_page_timeout.png')
                raise Exception('Page timed out - aborting test')
            # Checking empty fields error messages
            password_field = WebDriverWait(driver, 30).until(
                EC.visibility_of_element_located((By.ID, 'password-field')))
            password_field.click()
            email_field = WebDriverWait(driver, 30).until(
                EC.visibility_of_element_located((By.ID, 'email-field')))
            email_field.click()
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Login credentials required')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Password is required')]")))
                logger.info('Empty fields error messages are shown')
                time.sleep(1)
                driver.save_screenshot(path + 'login_checks_empty_fields_error.png')
                # api.attachments.add_attachment_to_run(new_test_run['id'], path + 'login_checks_empty_fields_error.png')
            except TimeoutException:
                logger.warning('No error messages present for empty login fields!')
                driver.save_screenshot(path + 'login_checks_empty_fields_error_missing.png')
            # Checking incorrect username format error message
            try:
                email_field.send_keys('qa.automation@')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Invalid login credentials')]")))
                logger.info('Incorrect username format error message is shown')
                time.sleep(1)
                driver.save_screenshot(path + 'login_checks_incorrect_username_error_message.png')
            except TimeoutException:
                logger.warning('No error message present for incorrect username format')
                driver.save_screenshot(path + 'login_checks_incorrect_username_error_missing.png')
            # Checking login with non existing user
            try:
                email_field.send_keys('example')
                password_field.send_keys('test')
                WebDriverWait(driver, 20).until(
                    EC.visibility_of_element_located((By.ID, 'password-submit'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Invalid login credentials')]")))
                logger.info('Checked login with non existing user')
                driver.save_screenshot(path + 'login_checks_nonexistent_user.png')
            except TimeoutException:
                logger.warning('No error message present for login with non existent user')
                driver.save_screenshot(path + 'login_checks_nonexistent_user_missing.png')
            # Checking forgot password page
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Forgot password?')]"))).click()
                WebDriverWait(driver, 30).until(EC.title_contains('Reset your password'))
                logger.info('Forgot password page is present')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'input-field'))).clear()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'input-field'))).send_keys('qa.automation@example.')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'The Email field is not a valid "
                                                                "e-mail address.')]")))
                logger.info('Invalid username format error message is shown')
                driver.save_screenshot(path + 'login_checks_forgot_password_invalid_username.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'input-field'))).clear()
                WebDriverWait(driver, 20).until(
                    EC.visibility_of_element_located((By.ID, 'submit-button'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'The Email field is required.')]")))
                logger.info('Empty field error message is shown')
                driver.save_screenshot(path + 'login_checks_forgot_password_empty_field.png')
            except TimeoutException:
                logger.warning('There was an issue with the forgot password page!')
                driver.save_screenshot(path + 'login_checks_forgot_password_issue.png')
            # Cancel and return to login page
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Cancel and return to login "
                                                                "page')]"))).click()
                WebDriverWait(driver, 30).until(EC.title_contains('Enter your login'))
                logger.info('Canceled forgot password and went back to login page')
            except TimeoutException:
                logger.warning('There was an issue cancelling forgot password and going back to the login page!')
                driver.save_screenshot(path + 'login_checks_cancel_forgot_password_issue.png')
            # Try valid login
            try:
                email = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'email-field')))
                if env == getenv('RI_STAGE'):
                    email.send_keys(getenv('RI_USER'))
                elif env == getenv('RI_STAGE_INTEGRATED'):
                    email.send_keys(getenv('RI_STAGE_INTEGRATED_USER'))
                elif env == getenv('RI_STAGE_EMEA'):
                    email.send_keys(getenv('RI_USER'))
                elif env == getenv('RI_TEST'):
                    email.send_keys(getenv('RI_USER'))
                elif env == getenv('RI_PROD_INTEGRATED'):
                    email.send_keys(getenv('RI_PROD_USER'))
                elif env == getenv('RI_PROD'):
                    email.send_keys(getenv('RI_PROD_USER'))
                elif env == getenv('RI_PROD_EMEA'):
                    email.send_keys(getenv('RI_PROD_USER'))
                password = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'password-field')))
                password.send_keys(os.environ.get('RI_PASS'))
                WebDriverWait(driver, 20).until(
                    EC.visibility_of_element_located((By.ID, 'password-submit'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'dashboard')))
                logger.info('Valid login checked')
            except TimeoutException:
                logger.critical('There was an issue login in - please check the screenshot!')
                driver.save_screenshot(path + 'login_issue.png')
                raise Exception

        # Go through all the pages / views and do some basic checks
        @staticmethod
        def test_basic_page_checks():
            logger.debug('UI test - Basic page checks')
            login()
            logger.debug('Going through all the pages / views of the app and doing some basic checks')
            # Dashboard
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Add Widget')]")))
                logger.info('Dashboard page loaded successfully')
                time.sleep(5)
                driver.save_screenshot(path + 'dashboard_page.png')
            except TimeoutException:
                logger.warning('The dashboard page did not load!')
                driver.save_screenshot(path + 'dashboard_page_issue.png')
                raise Exception
            # Scan Computers - must skip for integrated env
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                time.sleep(.5)
            else:
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'scan_other'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Choose Organization')]")))
                    logger.info('Scan Computers page loaded successfully')
                    driver.save_screenshot(path + 'scan_computers_page.png')
                    # Check Show Help tooltip
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.CLASS_NAME, 'iscan-help-toggle'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Scans the computer to "
                                                                    "discover "
                                                                    "sensitive data, who has access to that data, "
                                                                    "and vulnerabilities that could lead to a breach. "
                                                                    "Provides the most comprehensive view of cyber "
                                                                    "risk "
                                                                    "for a computer.')]")))
                    logger.info('Scan computer help tooltip is shown')
                    driver.save_screenshot(path + 'scan_computers_help_tooltip.png')
                except TimeoutException:
                    logger.warning('The scan computers page did not load!')
                    driver.save_screenshot(path + 'scan_computers_page_issue.png')
            # View and Manage - some items must be skipped for integrated env
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                driver.save_screenshot(path + 'view_manage_menu_list.png')
                # Open Scan Results
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Scan Results')]"))).click()
                logger.info('View and Manage - Scan Results page loaded successfully')
                time.sleep(15)
                driver.save_screenshot(path + 'view_manage_scan_results.png')
            except TimeoutException:
                logger.warning('View and manage Scan Results page did not load!')
                driver.save_screenshot(path + 'view_manage_scan_results_issue.png')
            # Open Devices Scanned
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                time.sleep(.5)
            else:
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                    "'Devices Scanned')]"))).click()
                    time.sleep(2)
                    logger.info('View and Manage - Devices Scanned page loaded successfully')
                    driver.save_screenshot(path + 'view_manage_devices_scanned.png')
                except TimeoutException:
                    logger.warning('View and manage Devices Scanned page did not load!')
                    driver.save_screenshot(path + 'view_manage_devices_scanned_issue.png')
            # Open Users
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Users')]"))).click()
                logger.info('View and Manage - Users page loaded successfully')
                time.sleep(3)
                driver.save_screenshot(path + 'view_manage_users.png')
            except TimeoutException:
                logger.warning('View and manage Users page did not load!')
                driver.save_screenshot(path + 'view_manage_users_issue.png')
            # Open Organizations - skip now for integrated env and check it later
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                time.sleep(.5)
            else:
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Organizations')]"))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Flat View')]")))
                    logger.info('View and Manage - Organizations page loaded successfully')
                    time.sleep(6)
                    driver.save_screenshot(path + 'view_manage_organizations_flat_view.png')
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Tree View')]"))).click()
                    time.sleep(3)
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Partner "
                                                                    "Device Licenses')]")))
                    driver.save_screenshot(path + 'view_manage_organizations_tree_view.png')
                except TimeoutException:
                    logger.warning('View and manage Organizations page did not load or there is an issue with the tree '
                                   'view!')
                    driver.save_screenshot(path + 'view_manage_organizations_issue.png')
            # Open Scan Configurations
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Configurations')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Add Scan Configuration')]")))
                logger.info('View and Manage - Scan Configurations page loaded successfully')
                time.sleep(5)
                driver.save_screenshot(path + 'view_manage_scan_configurations.png')
            except TimeoutException:
                logger.warning('View and manage Scan Configurations page did not load!')
                driver.save_screenshot(path + 'view_manage_scan_configurations_issue.png')
            # Open Scan Key Management
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                time.sleep(.5)
            else:
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Scan Key Management')]"))).click()
                    logger.info('View and Manage - Scan Key Management page loaded successfully')
                    time.sleep(5)
                    driver.save_screenshot(path + 'view_manage_scan_key_management.png')
                except TimeoutException:
                    logger.warning('View and manage Scan Key Management page did not load!')
                    driver.save_screenshot(path + 'view_manage_scan_key_management_issue.png')
            # Reports
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'reports'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Reports for')]")))
                    logger.info('Reports page loaded successfully')
                    time.sleep(6)
                    driver.save_screenshot(path + 'reports_page.png')
                except TimeoutException:
                    logger.warning('The reports page did not load!')
                    driver.save_screenshot(path + 'reports_page_issue.png')
            else:
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'reports'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Create New Report')]")))
                    logger.info('Reports page loaded successfully')
                    time.sleep(3)
                    driver.save_screenshot(path + 'reports_page.png')
                except TimeoutException:
                    logger.warning('The reports page did not load!')
                    driver.save_screenshot(path + 'reports_page_issue.png')
            # Customers - skip for integrated env
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                time.sleep(.5)
            else:
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'add_customer'))).click()
                    driver.save_screenshot(path + 'customers_menu_list.png')
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Add Customer')]"))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'New Account Creation')]")))
                    time.sleep(2)
                    logger.info('Customers - Add Customer page loaded successfully')
                    driver.save_screenshot(path + 'customers_add_customer_page.png')
                except TimeoutException:
                    logger.warning('The customers - add customer page did not load!')
                    driver.save_screenshot(path + 'customers_page_issue.png')
            # Current domain popup - different for integrated env
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Current VAR:')]"))).click()
                    field = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, "user_context_domain")))
                    field.click()
                    field.send_keys('ACME Enterprises Inc')
                    logger.info('Change context popup loaded successfully')
                    driver.save_screenshot(path + 'change_context_popup.png')
                    time.sleep(3)
                    actions = ActionChains(driver)
                    actions.send_keys(Keys.ARROW_DOWN)
                    time.sleep(1)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                    time.sleep(5)
                except TimeoutException:
                    logger.warning('The change context popup did not load!')
                    driver.save_screenshot(path + 'change_context_popup_issue.png')
            else:
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Current "
                                                                    "Domain:')]"))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, "user_context_domain")))
                    logger.info('Change domain popup loaded successfully')
                    driver.save_screenshot(path + 'change_domain_popup.png')
                    time.sleep(1)
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.CLASS_NAME, "close"))).click()
                except TimeoutException:
                    logger.warning('The change domain popup did not load!')
                    driver.save_screenshot(path + 'change_domain_popup_issue.png')
            # Organizations - step only for integrated env
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Organizations')]"))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Flat View')]")))
                    logger.info('View and Manage - Organizations page loaded successfully')
                    driver.save_screenshot(path + 'view_manage_organizations_flat_view.png')
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Tree View')]"))).click()
                    time.sleep(3)
                    WebDriverWait(driver, 60).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Partner Device Licenses')]")))
                    driver.save_screenshot(path + 'view_manage_organizations_tree_view.png')
                except TimeoutException:
                    logger.warning('View and manage Organizations page did not load or there is an issue with the tree '
                                   'view!')
                    driver.save_screenshot(path + 'view_manage_organizations_issue.png')
            else:
                time.sleep(.5)
            # Notifications
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'section_notification')]"))).click()
                logger.info('Notifications section is shown')
                time.sleep(3)
                driver.save_screenshot(path + 'notifications_section.png')
            except TimeoutException:
                logger.warning('The notifications section was not found!')
                driver.save_screenshot(path + 'notifications_section_issue.png')
            # Help
            main_page = driver.window_handles[0]
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'section_help')]"))).click()
                logger.info('The help section is shown, checking the links')
                driver.save_screenshot(path + 'help_section.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Risk Intelligence Knowledge Base')]"))).click()
                knowledge_page = driver.window_handles[1]
                driver.switch_to.window(knowledge_page)
                WebDriverWait(driver, 60).until(EC.title_contains('Knowledge Article'))
                logger.info('RI Knowledge Base page loaded successfully')
                time.sleep(3)
                driver.save_screenshot(path + 'help_knowledge_base_page.png')
                driver.switch_to.window(main_page)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'section_help')]"))).click()
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'User Manual')]"))).click()
                # different open tabs behaviour on firefox so need special case for it
                if driver.name == 'firefox':
                    user_manual_page = driver.window_handles[1]
                    driver.switch_to.window(user_manual_page)
                    WebDriverWait(driver, 60).until(EC.title_contains('User Guide'))
                    time.sleep(3)
                    logger.info('RI User Manual page loaded successfully')
                    driver.save_screenshot(path + 'help_user_manual.png')
                    driver.switch_to.window(main_page)
                else:
                    user_manual_page = driver.window_handles[2]
                    driver.switch_to.window(user_manual_page)
                    WebDriverWait(driver, 30).until(EC.title_contains('User Guide'))
                    time.sleep(3)
                    logger.info('RI User Manual page loaded successfully')
                    driver.save_screenshot(path + 'help_user_manual.png')
                    driver.switch_to.window(main_page)
            except TimeoutException:
                logger.warning('The help section was not found or there was an issue with the links inside!')
                driver.save_screenshot(path + 'help_section_issue.png')
                driver.switch_to.window(main_page)
            # Applications
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'switcher')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, "productLink-rmm")))
                logger.info('Applications section is shown')
                driver.save_screenshot(path + 'applications_section.png')
            except TimeoutException:
                logger.warning('The applications section was not found!')
                driver.save_screenshot(path + 'applications_section_issue.png')
            # User Account
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'section_account')]"))).click()
                logger.info('User account section is shown')
                driver.save_screenshot(path + 'user_account_section.png')
            except TimeoutException:
                logger.warning('The user account section was not found!')
                driver.save_screenshot(path + 'user_account_section_issue.png')
            # Logout
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Logout')]"))).click()
                WebDriverWait(driver, 30).until(EC.title_contains('Enter your login'))
                logger.info('Logout works correctly')
                driver.save_screenshot(path + 'logged_out.png')
            except TimeoutException:
                logger.warning('There was an issue trying to logout!')
                driver.save_screenshot(path + 'log_out_issue.png')

        # Check that you can create / edit a new user
        @staticmethod
        def test_create_edit_user():
            logger.debug('UI test - Create / edit a new user')
            login()
            change_context()
            logger.debug('Going to View and Manage - Users in order to add a new user')
            # Open View and Manage - Users - Add User
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Users')]"))).click()
                logger.info('View and Manage - Users page loaded successfully, clicking on Add User button')
            except TimeoutException:
                logger.critical('The Users page did not load or there was an issue, aborting test!')
                driver.save_screenshot(path + 'test_create_edit_user_users_page_issue.png')
                raise Exception
            # Check that user doesn't already exist before continuing with the test
            try:
                user = WebDriverWait(driver, 5).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI Automation Test User')]")))
                logger.info('User already exists, will delete before proceeding with the test')
                try:
                    actions = ActionChains(driver)
                    actions.double_click(user).perform()
                    WebDriverWait(driver, 10).until(EC.number_of_windows_to_be(2))
                    main_page = driver.window_handles[0]
                    user_page = driver.window_handles[1]
                    driver.switch_to.window(user_page)
                    driver.execute_script("scrollBy(0,+1000);")
                    WebDriverWait(driver, 10).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Delete')]"))).click()
                    WebDriverWait(driver, 5).until(EC.alert_is_present())
                    driver.switch_to.alert.accept()
                    driver.close()
                    WebDriverWait(driver, 10).until(EC.number_of_windows_to_be(1))
                    driver.switch_to.window(main_page)
                except TimeoutException:
                    logger.critical('Failed to delete existing user, aborting test!')
                    driver.save_screenshot(path + 'test_create_edit_user_add_user_delete_existing_issue.png')
                    raise Exception
            except TimeoutException:
                time.sleep(0.5)
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="pager_user_grid_left"]/table/tbody/tr/td[3]/div'))).click()
                add_user_page = driver.window_handles[1]
                driver.switch_to.window(add_user_page)
                logger.info('Add user page opened, proceeding with creating a new user')
                time.sleep(3)
                driver.save_screenshot(path + 'test_create_edit_user_add_user_page.png')
            except TimeoutException:
                logger.critical('The Add User page did not load!')
                driver.save_screenshot(path + 'test_create_edit_user_add_user_page_issue.png')
                raise Exception
            # Add a new user
            try:
                # Adding higher wait time here due to an issue on firefox, if you click on Add User before the list
                # loads some checkboxes won't appear, one of which needed for the test
                time.sleep(10)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[2]/div[3]/div/div/div['
                                                      '1]/div[2]/button'))).click()
                full_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[2]/div[3]/div/div/div['
                                                      '2]/div/div/div[2]/form/div[1]/input')))
                full_name.send_keys('RI Automation Test User')
                email = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[2]/div[3]/div/div/div['
                                                      '2]/div/div/div[2]/form/div[2]/input')))
                email.send_keys('riskintelligence42+ri_test_user@gmail.com')
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[2]/div[3]/div/div/div['
                                                      '2]/div/div/div[2]/form/div[5]/label/input'))).click()
                driver.execute_script("scrollBy(0,+500);")
                time.sleep(1)
                driver.save_screenshot(path + 'test_create_edit_user_add_user_page_filled_fields.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'button[ng-click="save(user)"]'))).click()
                time.sleep(3)
                name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[ng-model="colFilter.term"]')))
                name.send_keys('RI Automation Test User')
                time.sleep(3)
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI "
                                                                                            "Automation Test "
                                                                                            "User')]")))
                logger.info('The new user was created successfully!')
                driver.save_screenshot(path + 'test_create_edit_user_new_user_saved.png')
            except TimeoutException or UnexpectedAlertPresentException:
                logger.critical('There was an issue creating the user - please check the screenshot!')
                driver.save_screenshot(path + 'test_create_edit_user_user_creation_issue.png')
                raise Exception
            # Edit the user
            logger.debug('Proceeding with the test - edit user')
            try:
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.CSS_SELECTOR, 'button[ng-click="grid.appScope.editUser(row.entity)"]'))).click()
                full_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.NAME, 'fullname')))
                full_name.send_keys(' (edited)')
                driver.execute_script("scrollBy(0,+1000);")
                time.sleep(1)
                driver.save_screenshot(path + 'test_create_edit_user_edit_user_filled_fields.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'button[ng-click="save(user)"]'))).click()
                time.sleep(1)
                driver.refresh()
                time.sleep(1)
                name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[ng-model="colFilter.term"]')))
                name.send_keys('RI Automation Test User')
                time.sleep(3)
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI "
                                                                                            "Automation Test "
                                                                                            "User (edited)')]")))
                logger.info('The user was edited successfully!')
                driver.save_screenshot(path + 'test_create_edit_user_edited_user_saved.png')
            except TimeoutException:
                logger.warning('Could not edit the user, please check the screenshot!')
                driver.save_screenshot(path + 'test_create_edit_user_edit_user_issue.png')
                raise Exception

        # Check deleting the newly created user
        @staticmethod
        def test_delete_user():
            logger.debug('UI test - Delete user')
            login()
            change_context()
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Users')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="pager_user_grid_left"]/table/tbody/tr/td[3]/div'))).click()
                add_user_page = driver.window_handles[1]
                driver.switch_to.window(add_user_page)
            except TimeoutException:
                logger.critical('The Users page did not load or there was an issue, aborting test!')
                driver.save_screenshot(path + 'test_delete_user_users_page_issue.png')
                raise Exception
            try:
                name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[ng-model="colFilter.term"]')))
                name.send_keys('RI Automation Test User')
                time.sleep(2)
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.CSS_SELECTOR, 'button[ng-click="grid.appScope.deleteUser(row.entity)"]'))).click()
                WebDriverWait(driver, 10).until(EC.alert_is_present())
                logger.info('First delete user message popup is shown - ' + driver.switch_to.alert.text)
                driver.switch_to.alert.accept()
                time.sleep(1)
                WebDriverWait(driver, 10).until(EC.alert_is_present())
                logger.info('Second delete user message popup is shown - ' + driver.switch_to.alert.text)
                driver.switch_to.alert.accept()
                time.sleep(1)
                driver.refresh()
                name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[ng-model="colFilter.term"]')))
                name.send_keys('RI Automation Test User')
                time.sleep(3)
                try:
                    WebDriverWait(driver, 5).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI "
                                                                    "Automation Test "
                                                                    "User (edited)')]")))
                    logger.critical('The user is still present in the list!')
                    driver.save_screenshot(path + 'test_delete_user_issue.png')
                except TimeoutException:
                    logger.info('The user was deleted successfully!')
                    driver.save_screenshot(path + 'test_delete_user_success.png')
            except TimeoutException:
                logger.critical('There was an issue deleting the user - please check the screenshot!')
                driver.save_screenshot(path + 'test_delete_user_issue.png')
                raise Exception

        # Check that you can create / edit a new organization - skip for integrated env.
        @staticmethod
        def test_create_edit_organization():
            logger.debug('UI test - Create / edit a new organization')
            # First let's check via API if org. already exists somehow and if so delete it
            try:
                response = requests.get(
                    env + '/organizations.json?auth_token=' + api_token, json={"name": "RI Automation Test Organization"})
                data = response.json()
                org_exists = data['total_count']
                if org_exists == 1:
                    logger.info('Organization already exists, will delete before proceeding with test')
                    existingorg_id = data['rows'][0]['id']
                    response = requests.delete(
                        env + '/organizations/' + str(existingorg_id) + '?auth_token=' + api_token)
                    if response.status_code == 200:
                        logger.info(
                            'Organization was deleted, will continue with the test')
                    else:
                        logger.critical(
                            'There was an issue with the request: status code ' + str(
                                response.status_code) + ' - ' + str(
                                response.content))
                        raise Exception
                else:
                    time.sleep(0.5)
            except requests.exceptions.RequestException as e:
                logger.critical('RI is not reachable - error: ' + str(e))
                raise Exception
            login()
            logger.debug('Going to Customers - Add customer in order to add a new organization')
            # Open Customers - Add customer
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'add_customer'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Add Customer')]"))).click()
                logger.info(
                    'Customers - Add customer page loaded successfully, proceeding to the next step with Retail '
                    'selected')
            except TimeoutException:
                logger.critical('The Add Customer page did not load or there was an issue, aborting test!')
                driver.save_screenshot(path + 'add_customer_page_issue.png')
                raise Exception
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/div[4]/div/div/div/div[1]'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/div[4]/div/div/button'))).click()
                logger.info(
                    'Add Organization Account info page is shown, proceeding with creating a new organization')
                time.sleep(3)
                driver.save_screenshot(path + 'add_organization_step_2.png')
            except TimeoutException:
                logger.critical('The Add Organization Account Info page did not load!')
                driver.save_screenshot(path + 'add_organization_account_info_page_issue.png')
                raise Exception
            # Add new organization account information
            try:
                company_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[4]/div/div/div[2]/form/div['
                                                      '1]/div/input')))
                company_name.send_keys('RI Automation Test Organization')
                state_province = Select(
                    driver.find_element(By.XPATH, "//select[@ng-model='organization.state']"))
                state_province.select_by_visible_text('Alaska')
                full_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[4]/div/div/div[2]/form/div['
                                                      '8]/div[1]/input')))
                full_name.send_keys('RI Automation Test Organization')
                email = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[4]/div/div/div[2]/form/div['
                                                      '8]/div[2]/input')))
                email.send_keys('riskintelligence42+ri_test_organization@gmail.com')
                time.sleep(3)
                driver.save_screenshot(path + 'add_organization_step_2_filled_fields.png')
                # Click on next, leave default values and screenshot step 3
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                time.sleep(3)
                driver.save_screenshot(path + 'add_organization_step_3.png')
                # Click on next and screenshot step 4 then save the org.
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                time.sleep(3)
                driver.save_screenshot(path + 'add_organization_step_4.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Save')]"))).click()
                time.sleep(10)
                # New organization Confirmation page
                WebDriverWait(driver, 60).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                "'Account "
                                                                "Info')]")))
                logger.info('The new organization was created successfully!')
                driver.save_screenshot(path + 'new_organization_saved.png')
            except TimeoutException:
                logger.critical('There was an issue creating the organization - please check the screenshot!')
                driver.save_screenshot(path + 'add_organization_issue.png')
                raise Exception
            # Edit the organization
            logger.debug('Proceeding with the test - edit organization')
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                "'Account "
                                                                "Info')]"))).click()
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH,
                     '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[1]/div[1]/span'))).click()
                time.sleep(5)
                org_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.NAME, 'name')))
                org_name.send_keys(' (edited)')
                time.sleep(3)
                driver.save_screenshot(path + 'edit_organization_filled_fields.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div['
                                                      '1]/div[2]/div/button'))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI "
                                                                "Automation Test "
                                                                "Organization (edited)')]")))
                logger.info('The organization was edited successfully!')
                driver.save_screenshot(path + 'edited_organization_saved.png')
            except TimeoutException:
                logger.warning('Could not edit the organization, please check the screenshot!')
                driver.save_screenshot(path + 'edit_organization_issue.png')

        # Verify that a new organization has all the default scans - skip for integrated env.
        @staticmethod
        def test_verify_default_scans():
            logger.debug('UI test - Verify default scans')
            login()
            logger.debug('Changing context to organization with default scans')
            # Open Current Domain and Current Organization and change context
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'context-btn'))).click()
                time.sleep(5)
                organization_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'user_context_organization')))
                organization_name.click()
                organization_name.send_keys('RI Automation Test Organization (edited)')
                actions = ActionChains(driver)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                time.sleep(3)
                try:
                    WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'RI Automation Test Organization (edited)')]")))
                    logger.info('Context changed successfully!')
                    time.sleep(1)
                    driver.save_screenshot(path + 'default_scans_change_context_successful.png')
                except TimeoutException:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'context-btn'))).click()
                    time.sleep(5)
                    organization_name = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'user_context_organization')))
                    organization_name.click()
                    organization_name.send_keys('RI Automation Test Organization (edited)')
                    actions = ActionChains(driver)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                    time.sleep(3)
                    WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'RI Automation Test Organization (edited)')]")))
                    logger.info('Context changed successfully!')
                    time.sleep(1)
                    driver.save_screenshot(path + 'default_scans_change_context_successful.png')
            except TimeoutException:
                logger.critical('There was an issue changing the context, aborting test!')
                driver.save_screenshot(path + 'default_scans_change_context_page_issue.png')
                raise Exception
            # Go to View and Manage > Scan Configurations
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Configurations')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Add Scan Configuration')]")))
                logger.info('Default scans - Scan Configurations page loaded successfully')
                time.sleep(5)
                driver.save_screenshot(path + 'default_scans_view_manage_scan_configurations.png')
            except TimeoutException:
                logger.warning('Default scans - Scan Configurations page did not load!')
                driver.save_screenshot(path + 'default_scans_view_manage_scan_configurations_issue.png')
            # Check default scans list
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Security Scan')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - USA')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - GBR')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - AUS')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - SWE')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - NOR')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - CAN')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - NLD')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - BEL')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - BRA')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - ESP')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - ITA')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - FRA')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - IRL')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - DEU')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - NZL')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Data Breach Risk Scan - ZAF')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'PCI and PAN Scan')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Expanded Data Breach Scan')]")))
                logger.info('The default scans are present!')
                driver.save_screenshot(path + 'default_scans_scan_configurations.png')
            except TimeoutException:
                logger.critical('One or more of the default scans are missing, please check the screenshot!')
                driver.save_screenshot(path + 'default_scans_missing_issue.png')
                raise Exception

        # Delete the organization
        @staticmethod
        def test_delete_organization():
            logger.debug('UI test - Delete organization')
            login()
            # Go to View and Manage - Organizations
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                driver.save_screenshot(path + 'delete_organization_view_manage_menu_list.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Organizations')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Flat View')]")))
                logger.info('View and Manage - Organizations page loaded successfully')
                time.sleep(6)
                driver.save_screenshot(path + 'delete_organization_view_manage_organizations.png')
            except TimeoutException:
                logger.warning('View and manage Organizations page did not load or there is an issue')
                driver.save_screenshot(path + 'delete_organization_view_manage_organizations_issue.png')
            # Search for existing organization and delete it
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.CSS_SELECTOR, 'input[ng-model="colFilter.term"]'))).click()
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys('RI Auto')
                actions.perform()
                time.sleep(6)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI Automation Test "
                                                                "Organization (edited)')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'button[ng-click="openOrg()"]'))).click()
            except TimeoutException:
                logger.warning('Could not find organization')
                driver.save_screenshot(path + 'delete_organization_search_organizations_issue.png')
            try:
                new_window = driver.window_handles[1]
                driver.switch_to.window(new_window)
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                                            "'Account "
                                                                                            "Info')]"))).click()
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Delete this Account')]"))).click()
                logger.info('Delete organization message popup is shown - ' + driver.switch_to.alert.text)
                driver.switch_to.alert.accept()
                time.sleep(5)
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.CSS_SELECTOR, 'input[ng-model="colFilter.term"]'))).click()
                    actions = ActionChains(driver)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys('RI Auto')
                    actions.perform()
                    WebDriverWait(driver, 5).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI "
                                                                    "Automation Test "
                                                                    "Organization (edited)')]")))
                    logger.critical(
                        'There was an issue deleting the organization, please check the screenshot!')
                    driver.save_screenshot(path + 'delete_organization_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info('The organization was deleted successfully!')
                    driver.save_screenshot(path + 'delete_organization_successfully.png')
            except TimeoutException:
                logger.critical('There was an issue deleting the organization - please check the screenshot!')
                driver.save_screenshot(path + 'delete_organization_issue.png')
                raise Exception

        # Check that you can create / edit a new domain
        @staticmethod
        def test_create_edit_domain():
            logger.debug('UI test - Create / edit a new domain')
            login()
            logger.debug('Going to Customers - Add customer in order to add a new domain')
            # Open Customers - Add customer
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'add_customer'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Add Customer')]"))).click()
                logger.info('Customers - Add customer page loaded successfully, clicking on Domain type button')
            except TimeoutException:
                logger.critical('The Customers - Add customer page did not load or there was an issue, aborting test!')
                driver.save_screenshot(path + 'domain_page_issue.png')
                raise Exception
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'iScan Partner')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                logger.info('Add Domain Account info page opened, proceeding with creating a new domain')
                time.sleep(3)
                driver.save_screenshot(path + 'add_domain_step_2.png')
            except TimeoutException:
                logger.critical('The Add Domain Account Info page did not load!')
                driver.save_screenshot(path + 'add_domain_account_info_page_issue.png')
                raise Exception
            # Add new domain account information
            try:
                company_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[4]/div/div/div[2]/form/div['
                                                      '1]/div/input')))
                company_name.send_keys('RI Automation Test Domain')
                state_province = Select(driver.find_element(By.XPATH, "//select[@ng-model='organization.state']"))
                state_province.select_by_visible_text('Alaska')
                full_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[4]/div/div/div[2]/form/div['
                                                      '8]/div[1]/input')))
                full_name.send_keys('RI Automation Test Domain')
                email = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[4]/div/div/div[2]/form/div['
                                                      '8]/div[2]/input')))
                email.send_keys('riskintelligence42+ri_test_domain@gmail.com')
                time.sleep(1)
                driver.save_screenshot(path + 'add_domain_step_2_filled.png')
                # Click on next, leave default values and screenshot step 3
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                time.sleep(3)
                driver.save_screenshot(path + 'add_domain_step_3.png')
                # Click on next and screenshot step 4 then save the org.
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                time.sleep(3)
                driver.save_screenshot(path + 'add_domain_step_4.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Save')]"))).click()
                # New domain Confirmation page
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Account Info')]"))).click()
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'RI Automation Test Domain')]")))
                logger.info('The new domain was created successfully!')
                driver.save_screenshot(path + 'add_domain_successful.png')
            except TimeoutException:
                logger.critical('There was an issue creating the domain - please check the screenshot!')
                driver.save_screenshot(path + 'add_domain_issue.png')
                raise Exception
            # Edit the domain
            try:
                logger.debug('Proceeding with the test - edit domain')
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, '//*[@id="main-panel"]/div[2]/ul/li[1]/a'))).click()
                time.sleep(5)
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH,
                     '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[1]/div[1]/span'))).click()
                org_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.NAME, 'name')))
                org_name.send_keys(' (edited)')
                time.sleep(3)
                driver.save_screenshot(path + 'edit_domain_filled_fields.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div['
                                                      '1]/div[2]/div/button'))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI "
                                                                "Automation Test "
                                                                "Domain (edited)')]")))
                logger.info('The domain was edited successfully!')
                driver.save_screenshot(path + 'edited_domain_saved.png')
            except TimeoutException:
                logger.warning('Could not edit the domain, please check the screenshot!')
                driver.save_screenshot(path + 'edit_domain_issue.png')
                raise Exception

        # Check that you can delete the new domain
        @staticmethod
        def test_delete_domain():
            logger.debug('UI test - Delete the new domain')
            login()
            # Open Customers, search for existing domain and edit it
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Domains')]"))).click()
                logger.info('View and Manage - Domains page loaded successfully')
                time.sleep(5)
            except TimeoutException:
                logger.critical('View and manage Domains page did not load!')
                driver.save_screenshot(
                    path + 'test_delete_domain_view_manage_organization_issue.png')
                raise Exception
            try:
                domain_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, "gs_name")))
                domain_name.click()
                domain_name.send_keys('RI Automation Test Domain (edited)')
                time.sleep(1)
                actions = ActionChains(driver)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//td[@aria-describedby='table_domain_grid_name']"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="pager_domain_grid_left"]/table/tbody/tr/td[2]/div'))).click()
                # Switch to a new tab to edit the domain
                user_page = driver.window_handles[1]
                driver.switch_to.window(user_page)
                logger.info('The existing domain was successfully opened')
                driver.save_screenshot(path + 'test_delete_domain_search_successful.png')
            except TimeoutException:
                logger.critical('The domain was not found, please check the screenshot!')
                driver.save_screenshot(path + 'test_delete_domain_search_issue.png')
                raise Exception
            # Delete the domain
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/fieldset[1]/a'))).click()
                driver.switch_to.alert.accept()
                time.sleep(3)
                domain_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, "gs_name")))
                domain_name.click()
                domain_name.send_keys('RI Automation Test Domain')
                time.sleep(1)
                actions = ActionChains(driver)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                try:
                    WebDriverWait(driver, 3).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'RI Automation Test Domain (edited)')]")))
                    logger.critical('Could not delete the domain, please check the screenshot!')
                    driver.save_screenshot(path + 'test_delete_domain_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info('The domain was deleted successfully!')
                    driver.save_screenshot(path + 'test_delete_domain successful.png')
            except TimeoutException:
                logger.critical('Could not delete the domain, please check the screenshot!')
                driver.save_screenshot(path + 'test_delete_domain_issue.png')
                raise Exception

        # Create a new scan configuration, then delete it
        @staticmethod
        def test_create_delete_scan_config():
            logger.debug('UI test - Create / delete new scan configuration')
            login()
            logger.debug('Going to View and Manage - Scan configurations')
            # Open View and Manage  - Scan configurations
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Configurations')]"))).click()
                logger.info(
                    'View and Manage - Scan Configurations page loaded successfully, clicking on Add Scan '
                    'Configurations')
            except TimeoutException:
                logger.critical('The Scan Configurations page did not load or there was an issue, aborting test!')
                driver.save_screenshot(path + 'scan_configurations_page_issue.png')
                raise Exception
            time.sleep(10)
            driver.execute_script("scrollBy(0,+10000);")
            time.sleep(1)
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Add Scan Configuration')]"))).click()
                logger.info('Add Scan Configuration page opened, proceeding with creating a new scan')
                time.sleep(5)
            except TimeoutException:
                logger.critical('The Add Scan Configuration page did not load!')
                driver.save_screenshot(path + 'add_scan_configuration_page_issue.png')
                raise Exception
            # Select scan type
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         '//*[@id="main-panel"]/div[2]/div/div[1]/div[2]/div/div[4]/form/div/div[1]/div/div/div[1]/div'))).click()
                driver.save_screenshot(path + 'add_scan_configuration_type.png')
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                logger.info(
                    'Scan Type page is shown, proceeding with adding scan options')
                time.sleep(3)
                driver.save_screenshot(path + 'add_scan_configuration_options.png')
            except TimeoutException or ElementClickInterceptedException:
                logger.critical('The Scan Type page did not load!')
                driver.save_screenshot(path + 'add_scan_configuration_type_page_issue.png')
                raise Exception
            time.sleep(1)
            # Add scan options
            try:
                scan_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'name')))
                scan_name.send_keys('RI Automation Test Scan')
                driver.save_screenshot(path + 'add_scan_configuration_options_filled.png')
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Save Scan Configuration')]"))).click()
                # New scan configuration Confirmation page
                driver.execute_script("scrollBy(0,+500);")
                time.sleep(1)
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'RI Automation Test Scan')]")))
                logger.info('The new scan configuration was created successfully!')
                driver.save_screenshot(path + 'new_scan_configuration_saved.png')
            except TimeoutException:
                logger.critical('There was an issue creating the scan configuration - please check the screenshot!')
                driver.save_screenshot(path + 'add_scan_configuration_issue.png')
                raise Exception
            # Delete scan configuration
            try:
                time.sleep(1)
                driver.refresh()
                time.sleep(10)
                driver.execute_script("scrollBy(0,+10000);")
                time.sleep(1)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'RI Automation Test Scan')]"))).click()
                time.sleep(1)
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.SPACE)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                time.sleep(2)
                logger.info('Delete scan message popup is shown - ' + driver.switch_to.alert.text)
                time.sleep(1)
                driver.switch_to.alert.accept()
                time.sleep(5)
                driver.execute_script("scrollBy(0,+10000);")
                time.sleep(1)
                try:
                    WebDriverWait(driver, 5).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'RI Automation Test Scan')]")))
                    logger.critical('The new scan configuration was not deleted!')
                    driver.save_screenshot(path + 'new_scan_configuration_delete_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info('The new scan configuration was deleted successfully!')
                    driver.save_screenshot(path + 'new_scan_configuration_deleted.png')
            except TimeoutException:
                logger.critical('There was an issue deleting the scan configuration - please check the screenshot!')
                driver.save_screenshot(path + 'delete_scan_configuration_issue.png')
                raise Exception

        # Check changing context
        @staticmethod
        def test_change_context():
            logger.debug('UI test - Change context')
            login()
            change_context()
            logger.info('Context changed successfully!')

        # Create a new report and run it - skip for integrated env.
        @staticmethod
        def test_create_new_report():
            logger.debug('UI test - Create new report')
            login()
            # Search for existing Organization and Domain and change context
            change_context()
            # Open Reports
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'reports'))).click()
                time.sleep(1)
                driver.execute_script("scrollBy(0,+10000);")
                time.sleep(1)
                # Failsafe check that report doesn't already exist to avoid issues
                try:
                    driver.execute_script("scrollBy(0,+3000);")
                    report = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                    logger.info('Report already exist, will delete it before proceeding with the test')
                    if 'chrome' in wbdrv:
                        actions = ActionChains(driver)
                        actions.move_to_element_with_offset(report, 50, 50).click()
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.ENTER)
                        time.sleep(1)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ENTER)
                        actions.perform()
                    elif 'firefox' in wbdrv:
                        actions = ActionChains(driver)
                        actions.move_to_element_with_offset(report, 30, 30).click()
                        time.sleep(1)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.ENTER)
                        time.sleep(1)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ENTER)
                        actions.perform()
                    time.sleep(3)
                    try:
                        driver.switch_to.alert.accept()
                    except selenium.common.exceptions.NoAlertPresentException:
                        time.sleep(1)
                except TimeoutException:
                    time.sleep(1)
                driver.execute_script("scrollBy(0,200000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Create New Report')]")))
                logger.info('Reports page loaded successfully')
                time.sleep(3)
            except TimeoutException:
                logger.critical('The reports page did not load!')
                driver.save_screenshot(path + 'create_new_report_reports_page_issue.png')
                raise Exception
            try:
                driver.execute_script("scrollBy(0,200000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Create New Report')]"))).click()
                logger.info('The Create Report page opened successfully')
                time.sleep(5)
            except TimeoutException:
                logger.critical('The Create Report page did not load or there was an issue, aborting test!')
                driver.save_screenshot(path + 'reports_page_issue.png')
                raise Exception
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Security and Data Breach Reports')]"))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                time.sleep(3)
                driver.execute_script("scrollBy(0,500);")
                WebDriverWait(driver, 60).until(EC.visibility_of_element_located(
                    (By.XPATH,
                     '//*[@id="main-panel"]/div[2]/div[3]/ng-form/div[5]/div/div[1]/div/div/div[7]/div'))).click()
                driver.execute_script("scrollBy(0,1080);")
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                # Add report name
                report_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         '//*[@id="main-panel"]/div[2]/div[3]/ng-form/div[5]/div/div[1]/div/div[1]/div/input')))
                report_name.send_keys('Automation Test Report')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                logger.info('The report was completed successfully!')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Save')]"))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.ID, "main-panel"))).click()
                driver.execute_script("scrollBy(0,200000);")
            except TimeoutException:
                logger.critical('There was an issue completing the report. Please check the screenshot!')
                driver.save_screenshot(path + 'create_new_report_complete_issue.png')
                raise Exception
            try:
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                logger.info('The report was saved successfully!')
                driver.save_screenshot(path + 'create_new_report_successful.png')
            except TimeoutException:
                logger.critical('There was an issue saving the report. Please check the screenshot')
                driver.save_screenshot(path + 'create_new_report_save_issue.png')
                raise Exception
            try:
                logger.debug('Proceeding with generating report data')
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report')]"))).click()
                time.sleep(3)
                # Switch to new tab to verify report has been generated
                new_tab = driver.window_handles[1]
                driver.switch_to.window(new_tab)
                WebDriverWait(driver, 120).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                time.sleep(5)
                driver.save_screenshot(path + 'create_new_report_data_generated.png')
                logger.info('The report data has been generated')
            except TimeoutException:
                logger.critical('The report data could not be generated! Please check the attached screenshot')
                driver.save_screenshot(path + 'create_new_report_data_generation_issue.png')
                raise Exception
            # Delete the report to prevent clutter
            main = driver.window_handles[0]
            driver.switch_to.window(main)
            try:
                time.sleep(1)
                driver.refresh()
                time.sleep(5)
                driver.execute_script("scrollBy(0,+10000);")
                time.sleep(1)
                report = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                if 'chrome' in wbdrv:
                    actions = ActionChains(driver)
                    actions.move_to_element_with_offset(report, 50, 50).click()
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                elif 'firefox' in wbdrv:
                    actions = ActionChains(driver)
                    actions.move_to_element_with_offset(report, 40, 40).click()
                    time.sleep(1)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                WebDriverWait(driver, 10).until(EC.alert_is_present())
                logger.info('Delete report message popup is shown - ' + driver.switch_to.alert.text)
                WebDriverWait(driver, 10).until(EC.alert_is_present()).accept()
                time.sleep(5)
                driver.execute_script("scrollBy(0,+10000);")
                time.sleep(1)
                try:
                    WebDriverWait(driver, 5).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                    logger.critical('The report was not deleted!')
                    driver.save_screenshot(path + 'create_new_report_delete_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info('The report was deleted successfully!')
                    driver.save_screenshot(path + 'create_new_report_deleted_successfully.png')
            except TimeoutException:
                logger.critical(
                    'There was an issue deleting the report!')
                driver.save_screenshot(path + 'create_new_report_delete_issue.png')
                raise Exception

        # Verify that the scan device was added - dependency on the check scan test
        @staticmethod
        def test_scan_device_added():
            logger.debug('UI test - Check scan device is added')
            login()
            change_context()
            # Navigate to View and Manage - Devices Scanned
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                "'Devices Scanned')]"))).click()
                time.sleep(2)
                logger.info('View and Manage - Devices Scanned page loaded successfully')
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.CLASS_NAME, 'ui-jqgrid-title'))).click()
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys('RIDNSF')
                actions.send_keys(Keys.ENTER)
                actions.perform()
                WebDriverWait(driver, 15).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                "'RIDNSF')]"))).click()
                logger.info('Scan device was found in the list!')
                driver.save_screenshot(path + 'scan_device_added_listed.png')
                time.sleep(1)
            except TimeoutException:
                logger.warning('Either the scanned device is missing or there is an issue with the test!')
                driver.save_screenshot(path + 'scan_device_added_issue.png')

        # Check that SSO login / log out works correctly on Integrated env.
        @staticmethod
        def test_integrated_sso():
            logger.debug('UI test - Check SSO login / log out')
            login()
            time.sleep(3)
            # Switch to a new tab, and open RMM dashboard
            try:
                ri_window = driver.current_window_handle
                driver.execute_script("window.open();")
                driver.switch_to.window(driver.window_handles[1])
                if env == getenv('RI_PROD_INTEGRATED'):
                    driver.get("https://dashboard.systemmonitor.us/")
                elif env == getenv('RI_STAGE_INTEGRATED'):
                    driver.get("https://rmm-docker-test-minsk-01.swimsp.io/dashboard/")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "rmm-platform-bar")))
                logger.info('The user has also been logged into RMM')
                driver.save_screenshot(path + 'test_integrated_sso_login_successful.png')
            except TimeoutException:
                logger.critical('The user has not been logged into RMM! Please check the screenshot')
                driver.save_screenshot(path + 'test_integrated_sso_rmm_login_issue.png')
                raise Exception
            # Switch back to RI and logout
            try:
                driver.switch_to.window(ri_window)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "myAccount"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="submenu-#lnhUserAccount"]/li[8]/a'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "login-view")))
                logger.info('The user has been logged out of RI')
                driver.save_screenshot(path + 'test_integrated_sso_ri_logout_successful.png')
            except TimeoutException:
                logger.critical('The user has not been logged out! Please check the screenshot')
                driver.save_screenshot(path + 'test_integrated_sso_ri_logout_issue.png')
                raise Exception
            # Switch to RMM and verify that the user has been logged out
            try:
                driver.switch_to.window(driver.window_handles[1])
                driver.refresh()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "login-view")))
                logger.info('The user has also been logged out of RMM')
                driver.save_screenshot(path + 'test_integrated_sso_rmm_logout_successful.png')
            except TimeoutException:
                logger.critical('The user has not been logged out of RMM! Please check the screenshot')
                driver.save_screenshot(path + 'test_integrated_sso_rmm_logout_issue.png')
                raise Exception

        # Check that reports can be generated on Integrated env.
        @staticmethod
        def test_integrated_report():
            logger.debug('UI test - Check Integrated report')
            login()
            # Change context first
            change_context()
            # Open the Reports page
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'reports'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Reports for Customer "
                                                                "Conference')]")))
                logger.info('Reports page loaded successfully')
                time.sleep(3)
            except TimeoutException:
                logger.warning('The reports page did not load!')
                driver.save_screenshot(path + 'integrated_report_reports_page_issue.png')
                raise Exception
            # Open a report from the list, and verify it is populated
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/table/tbody/tr[13]/td['
                                   '3]/div[3]/a'))).click()
                WebDriverWait(driver, 120).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Completed At')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         '//*[@id="iscanD3GridTable"]/div/div[1]/div/div/div[1]/div/div[1]/span'))).click()
                logger.info('Report has been generated successfully, please check the screenshot for reference')
                driver.save_screenshot(path + 'integrated_report_successfully_generated.png')
            except TimeoutException:
                logger.critical('The report data has not been generated. Please check the screenshot')
                driver.save_screenshot(path + 'integrated_report_generated_issue.png')
                raise Exception

        # Check the widget functionality on the dashboard
        @staticmethod
        def test_add_rename_delete_widget():
            logger.debug('UI test - Add/Rename/Delete widget')
            login()
            # Search for existing Organization and Domain and change context
            if env == getenv('RI_STAGE') or env == getenv('RI_STAGE_EMEA') or env == getenv('RI_PROD') or env == getenv('RI_PROD_EMEA'):
                change_context()
            # Add a widget
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/div/div[1]/div/button/span'))).click()
                time.sleep(1)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Volume of Scans by Month')]"))).click()
                # Save the layout
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/div/div[1]/button[2]'))).click()
                time.sleep(1)
                # Refresh the page, and check that the widget is present
                driver.refresh()
                time.sleep(1)
                driver.execute_script("scrollBy(0,+2080);")
                time.sleep(3)
                if 'us.ri.logicnow.com' in env:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[8]/div/div[1]/h3/span[1]')))
                if 'emea' in env:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[9]')))
                if '.iscanonline.com' in env:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[10]/div/div[1]/h3/span[1]')))
                logger.info("Newly added widget is present on the dashboard!")
                time.sleep(3)
                driver.save_screenshot(path + 'test_add_rename_delete_widget_successfully_added.png')
            except TimeoutException:
                logger.critical("Widget is not present on the dashboard!")
                driver.save_screenshot(path + 'test_add_rename_delete_widget_add_issue.png')
                raise Exception
            # Rename a widget
            try:
                if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH,
                             '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[8]/div/div[1]/h3/span[3]'))).click()
                if 'emea' in env:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH,
                             '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[9]/div/div[1]/h3/span[3]'))).click()
                if '.iscanonline.com' in env:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH,
                             '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[10]/div/div[1]/h3/span[3]'))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "/html/body/div[7]/div/div/div[2]/form/div/div/input"))).send_keys(' (edited)')
                # Save
                driver.save_screenshot(path + 'test_add_rename_delete_widget_rename_dialog.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'OK')]"))).click()
                time.sleep(1)
                driver.execute_script("scrollBy(0,-3080);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/div/div[1]/button[2]'))).click()
                time.sleep(1)
                driver.refresh()
                time.sleep(3)
                driver.execute_script("scrollBy(0,+2080);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Volume of Scans by Month (edited)')]")))
                logger.info("Widget has been renamed successfully!")
                driver.save_screenshot(path + 'test_add_rename_delete_widget_successfully_renamed.png')
            except TimeoutException:
                logger.critical("Widget has not been renamed!")
                driver.save_screenshot(path + 'test_add_rename_delete_widget_rename_issue.png')
                raise Exception
            # Delete a widget
            try:
                driver.execute_script("scrollBy(0,+2080);")
                if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH,
                             '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[8]/div/div[1]/h3/span[2]'))).click()
                if 'emea' in env:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH,
                             '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[9]/div/div[1]/h3/span[2]'))).click()
                if '.iscanonline.com' in env:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH,
                             '//*[@id="main-panel"]/div[2]/div/div[3]/div/div/div[10]/div/div[1]/h3/span[2]'))).click()
                driver.execute_script("scrollBy(0,-4240);")
                time.sleep(1)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/div/div[1]/button[2]'))).click()
                time.sleep(1)
                driver.refresh()
                time.sleep(3)
                driver.execute_script("scrollBy(0,+3080);")
                time.sleep(1)
                WebDriverWait(driver, 5).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Volume of Scans by Month (edited)')]")))
                logger.critical("Widget was not deleted successfully!")
                driver.save_screenshot(path + 'test_add_rename_delete_widget_delete_issue.png')
                raise Exception
            except TimeoutException:
                logger.info("Widget was deleted successfully!")
                time.sleep(3)
                driver.save_screenshot(path + 'test_add_rename_delete_widget_successfully_deleted.png')
            # Reset to default, and save
            try:
                driver.execute_script("scrollBy(0,-4240);")
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'button[ng-click="defaultWidgets()"]'))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, 'button[ng-click="save()"]'))).click()
                time.sleep(3)
                logger.info("Dashboard has been reset to default widgets")
            except TimeoutException:
                logger.critical("Could not reset dashboard to default widgets, please check the screenshot!")
                driver.save_screenshot(path + 'test_add_rename_delete_reset_issue.png')
                raise Exception
            except selenium.common.exceptions.ElementNotInteractableException:
                logger.critical("Could not reset dashboard to default widgets, please check the screenshot!")
                driver.save_screenshot(path + 'test_add_rename_delete_reset_issue.png')
                raise Exception

        # Check each of the scan delivery methods are present
        @staticmethod
        def test_scan_delivery_methods():
            logger.debug('UI test - Scan Delivery Methods')
            login()
            change_context()
            # Going to Scan Computers
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'scan_other'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Choose Organization')]")))
                logger.info('Scan Computers page loaded successfully')
            except TimeoutException:
                logger.warning('The scan computers page did not load!')
                driver.save_screenshot(path + 'scan_delivery_methods_scan_computers_page_issue.png')
            # Choose a scan type
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Data Discovery')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Choose Scan Delivery Method')]")))
            except TimeoutException:
                logger.critical("Could not open Scan Type")
                driver.save_screenshot(path + 'scan_delivery_methods_scan_type_issue.png')
                raise Exception
            # Verify methods for default option (CLI)
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Windows Option 1 (easiest option)')]")))
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Windows Option 2')]")))
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'macOS Option 1 (easiest option)')]")))
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'macOS Option 2')]")))
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Linux Option 1 (easiest option)')]")))
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Linux Option 2')]")))
                logger.info("Scan Delivery methods for CLI are present!")
                driver.save_screenshot(path + 'scan_delivery_methods_CLI_option.png')
            except TimeoutException:
                logger.critical("Scan delivery methods for CLI are not present!")
                driver.save_screenshot(path + 'scan_delivery_methods_CLI_issue.png')
            driver.execute_script("scrollBy(0,-3240);")
            # Choose Active Directory method
            try:
                scan_method = Select(
                    driver.find_element(By.ID, 'scan-deliveries'))
                scan_method.select_by_visible_text('Active Directory')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Risk Intelligence includes a powerful CLI')]")))
                logger.info("Scan Delivery method for Active Directory is present!")
                driver.save_screenshot(path + 'scan_delivery_methods_AD_option.png')
            except TimeoutException:
                logger.critical('The scan delivery method for Active Directory is not present!')
                driver.save_screenshot(path + 'scan_delivery_methods_AD_issue.png')
            # Choose N-Able N-Central method
            try:
                scan_method = Select(
                    driver.find_element(By.ID, 'scan-deliveries'))
                scan_method.select_by_visible_text('N-Able N-Central')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//*[contains(text(), 'Scheduling Scans Using N-Able MSP N-Central')]")))
                logger.info("Scan Delivery method for N-Central is present!")
                driver.save_screenshot(path + 'scan_delivery_methods_n_central_option.png')
            except TimeoutException():
                logger.critical('The scan delivery method for N-Central is not present!')
                driver.save_screenshot(path + 'scan_delivery_methods_n_central_issue.png')
            # Choose Email method
            try:
                scan_method = Select(
                    driver.find_element(By.ID, 'scan-deliveries'))
                scan_method.select_by_visible_text('Email')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//*[contains(text(), 'Feel free to edit the email below, just be sure to keep the scan URL "
                         "intact')]")))
                logger.info("Scan Delivery method for Email is present!")
                driver.save_screenshot(path + 'scan_delivery_methods_email_option.png')
            except TimeoutException():
                logger.critical('The scan delivery method for Email is not present!')
                driver.save_screenshot(path + 'scan_delivery_methods_email_issue')
            # Choose URL method
            try:
                scan_method = Select(
                    driver.find_element(By.ID, 'scan-deliveries'))
                scan_method.select_by_visible_text('URL')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan URL for Data Discovery')]")))
                logger.info("Scan Delivery method for URL is present!")
                driver.save_screenshot(path + 'scan_delivery_methods_URL_option.png')
            except TimeoutException():
                logger.critical('The scan delivery method for URL is not present!')
                driver.save_screenshot(path + 'scan_delivery_methods_URL_issue.png')
            # Choose Scan Now Button method
            try:
                scan_method = Select(
                    driver.find_element(By.ID, 'scan-deliveries'))
                scan_method.select_by_visible_text('Scan Now Button')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//*[contains(text(), 'Copy and paste the code below to integrate a scan button like the one "
                         "above for Data Discovery')]")))
                logger.info("Scan Delivery method for Scan Now Button is present!")
                driver.save_screenshot(path + 'scan_delivery_methods_button_option.png')
            except TimeoutException():
                logger.critical('The scan delivery method for Scan Now Button is not present!')
                driver.save_screenshot(path + 'scan_delivery_methods_button_issue.png')
            # Chose HTML / Javascript integration method
            try:
                scan_method = Select(
                    driver.find_element(By.ID, 'scan-deliveries'))
                scan_method.select_by_visible_text('HTML / Javascript Integration')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//*[contains(text(), 'Use the code below as a guide for auto detection and scan using iScan "
                         "Online Browser plugin or Mobile App')]")))
                logger.info("Scan Delivery method for HTML / JS is present!")
                driver.save_screenshot(path + 'scan_delivery_methods_HTML_JS_option.png')
            except TimeoutException():
                logger.critical('The scan delivery method for HTML / JS is not present!')
                driver.save_screenshot(path + 'scan_delivery_methods_HTML_JS_issue.png')

        # Check adding a new column in the scan results page then removing it
        @staticmethod
        def test_scan_results_add_remove_column():
            logger.debug('UI test - Scan Results - Add/Remove column')
            login()
            # Search for existing Organization and Domain and change context
            if env == getenv('RI_STAGE') or env == getenv('RI_STAGE_EMEA') or env == getenv('RI_PROD') or env == getenv(
                    'RI_PROD_EMEA'):
                change_context()
            # Go to View and Manage - Scan Results
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                # Open Scan Results
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Results')]"))).click()
                logger.info('View and Manage - Scan Results page loaded successfully')
                time.sleep(3)
            except TimeoutException:
                logger.critical('View and manage Scan Results page did not load!')
                driver.save_screenshot(path + 'test_scan_result_add_remove_column_view_manage_page_issue.png')
                raise Exception
            # Add a column to the Scan Results page
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="pager_scans_grid_left"]/table/tbody/tr/td[4]/div'))).click()
                # Select the Public IP column to be added - using keys for Windows env.
                element = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="colchooser_table_scans_grid"]/div/select/option[6]')))
                ActionChains(driver) \
                    .key_down(Keys.CONTROL) \
                    .click(element) \
                    .key_up(Keys.CONTROL) \
                    .perform()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "/html/body/div[7]/div[11]/div/button[1]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Public IP')]")))
                logger.info("View and manage Scan Results - New column added: Public IP")
                time.sleep(1)
                driver.save_screenshot(path + 'test_scan_results_add_remove_column_add_successful.png')
            except TimeoutException:
                logger.critical("View and manage Scan Results - The column could not be added!")
                driver.save_screenshot(path + 'test_scan_results_add_remove_column_add_issue.png')
                raise Exception
            # Remove the column from the Scan Results page
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="pager_scans_grid_left"]/table/tbody/tr/td[4]/div'))).click()
                # Select the Organizations column to be removed
                element = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="colchooser_table_scans_grid"]/div/select/option[6]')))
                ActionChains(driver) \
                    .key_down(Keys.CONTROL) \
                    .click(element) \
                    .key_up(Keys.CONTROL) \
                    .perform()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "/html/body/div[7]/div[11]/div/button[1]"))).click()
                time.sleep(1)
                try:
                    WebDriverWait(driver, 5).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Public IP')]")))
                    logger.critical("View and manage Scan Results - The column could not be removed!")
                    driver.save_screenshot(path + 'test_scan_results_add_remove_column_remove_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info("View and manage Scan Results - Public IP column removed")
                    time.sleep(1)
                    driver.save_screenshot(path + 'test_scan_results_add_remove_column_remove_successful.png')
            except TimeoutException:
                logger.critical("View and manage Scan Results - The column could not be removed!")
                driver.save_screenshot(path + 'test_scan_results_add_remove_column_remove_issue.png')
                raise Exception

        # Verify the scan result report and then delete it
        @staticmethod
        def test_scan_result_view_delete():
            logger.debug('UI test - Scan Results - View and Delete')
            login()
            # Open Current Domain and Current Organization - skip for integrated stage
            if env == getenv('RI_STAGE_INTEGRATED'):
                time.sleep(0.5)
            else:
                change_context()
            # Go to View and Manage - Scan Results
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                # Open Scan Results
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Results')]"))).click()
                logger.info('View and Manage - Scan Results page loaded successfully!')
                time.sleep(5)
            except TimeoutException:
                logger.critical('View and manage Scan Results page did not load!')
                driver.save_screenshot(path + 'test_scan_result_view_delete_view_manage_scan_results_issue.png')
                raise Exception
            # Select the latest scan and view the report
            try:
                device_hostname = WebDriverWait(driver, 5).until(EC.visibility_of_element_located(
                    (By.ID, "gs_device.hostname")))
                if env == getenv('RI_PROD_INTEGRATED'):
                    device_hostname.send_keys('MQA')
                else:
                    device_hostname.send_keys('RIDNSF')
                actions = ActionChains(driver)
                actions.send_keys(Keys.ENTER).perform()
                time.sleep(3)
                if env == getenv('RI_PROD_INTEGRATED'):
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'MQA')]"))).click()
                else:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'RIDNSF')]"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'View Report')]"))).click()
                # Switch to new tab to view report details
                main_page = driver.window_handles[0]
                report_page = driver.window_handles[1]
                driver.switch_to.window(report_page)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Assessment Completed On')]")))
                time.sleep(5)
                logger.info('The scan result report was successfully opened!')
                driver.save_screenshot(path + 'test_scan_result_view_delete_successfully_opened.png')
                driver.switch_to.window(main_page)
            except TimeoutException:
                logger.critical('There is an issue with the report, please check the screenshot!')
                driver.save_screenshot(path + 'test_scan_result_view_delete_open_report_issue.png')
                raise Exception
            # Delete the scan result - will skip for integrated env. and leave for firefox only
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                time.sleep(1)
            else:
                if 'firefox' in wbdrv:
                    try:
                        WebDriverWait(driver, 30).until(
                            EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Delete')]"))).click()
                        WebDriverWait(driver, 10).until(EC.alert_is_present())
                        logger.info('Delete scan result message popup is shown - ' + driver.switch_to.alert.text)
                        driver.switch_to.alert.accept()
                        time.sleep(1)
                        logger.info('The scan result was successfully deleted!')
                    except TimeoutException:
                        logger.critical('The scan result could not be deleted, please check the screenshot!')
                        driver.save_screenshot(path + 'test_scan_result_view_delete_result_delete_issue.png')
                        raise Exception

        # Check adding a new column in the devices scanned page then removing it
        @staticmethod
        def test_devices_scanned_add_remove_column():
            logger.debug('UI test - Devices Scanned - Add/Remove column')
            login()
            change_context()
            # Go to View and Manage - Devices Scanned
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Devices Scanned')]"))).click()
                logger.info('View and Manage - Devices Scanned page loaded successfully!')
                time.sleep(3)
            except TimeoutException:
                logger.critical('View and manage Devices Scanned page did not load!')
                driver.save_screenshot(
                    path + 'test_devices_scanned_add_remove_column_view_and_manage_issue.png')
                raise Exception
            # Add a column to the Devices Scanned page
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="pager_devices_grid_left"]/table/tbody/tr/td[5]/div'))).click()
                # Select the OS Version column to be added - using keys for Windows env.
                element = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="colchooser_table_devices_grid"]/div/select/option[11]')))
                ActionChains(driver) \
                    .key_down(Keys.CONTROL) \
                    .click(element) \
                    .key_up(Keys.CONTROL) \
                    .perform()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "/html/body/div[7]/div[11]/div/button[1]"))).click()
                time.sleep(1)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'OS Version')]")))
                logger.info("View and manage Devices Scanned - New column added: OS Version")
                time.sleep(1)
                driver.save_screenshot(path + 'test_devices_scanned_add_remove_column_add_successful.png')
            except TimeoutException:
                logger.critical("View and manage Devices Scanned - The column could not be added!")
                driver.save_screenshot(path + 'test_devices_scanned_add_remove_column_add_issue.png')
                raise Exception
            # Remove the column from the Devices Scanned page
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="pager_devices_grid_left"]/table/tbody/tr/td[5]/div'))).click()
                # Select the OS Version column to be removed
                element = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="colchooser_table_devices_grid"]/div/select/option[11]')))
                ActionChains(driver) \
                    .key_down(Keys.CONTROL) \
                    .click(element) \
                    .key_up(Keys.CONTROL) \
                    .perform()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "/html/body/div[7]/div[11]/div/button[1]"))).click()
                time.sleep(3)
                try:
                    WebDriverWait(driver, 3).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'OS Version')]")))
                    logger.critical("View and manage Devices Scanned - The column could not be removed!")
                    driver.save_screenshot(path + 'test_devices_scanned_add_remove_column_remove_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info("View and manage Devices Scanned - New column removed")
                    time.sleep(1)
                    driver.save_screenshot(path + 'test_devices_scanned_add_remove_column_remove_successful.png')
            except TimeoutException:
                logger.critical("View and manage Devices Scanned - The column could not be removed!")
                driver.save_screenshot(path + 'test_devices_scanned_add_remove_column_remove_issue.png')
                raise Exception

        # Check the scanned device summary page then delete it
        @staticmethod
        def test_devices_scanned_show_summary():
            logger.debug('UI test - Devices Scanned - Show Summary')
            login()
            change_context()
            # Go to View and Manage - Scanned Devices
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Devices Scanned')]"))).click()
                logger.info('View and Manage - Devices Scanned page loaded successfully')
                time.sleep(5)
            except TimeoutException:
                logger.critical('View and manage Devices Scanned page did not load!')
                driver.save_screenshot(
                    path + 'test_devices_scanned_show_summary_view_manage_scan_results_issue.png')
                raise Exception
            # Select the device and view the summary
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.CLASS_NAME, 'ui-jqgrid-title'))).click()
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys('RIDNSF')
                actions.send_keys(Keys.ENTER)
                actions.perform()
                WebDriverWait(driver, 15).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                "'RIDNSF')]"))).click()
                time.sleep(1)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Device Summary')]"))).click()
                # Switch to new tab to view device summary
                time.sleep(3)
                main_page = driver.window_handles[0]
                report_page = driver.window_handles[1]
                driver.switch_to.window(report_page)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Vulnerable Devices By Severity')]")))
                time.sleep(3)
                logger.info('The Device Summary was successfully opened')
                driver.save_screenshot(path + 'test_devices_scanned_show_summary_successfully_opened.png')
                driver.switch_to.window(main_page)
            except TimeoutException:
                logger.critical('The Device Summary could not be opened, please check the screenshot!')
                driver.save_screenshot(path + 'test_devices_scanned_show_summary_open_issue.png')
                raise Exception
            # Click on Edit for the Device Summary
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.CSS_SELECTOR, "#pager_devices_grid_left > table > tbody > tr > td:nth-child(2) > div > span"))).click()
                if 'chrome' in wbdrv:
                    main_page = driver.window_handles[0]
                    report_page = driver.window_handles[2]
                    driver.switch_to.window(report_page)
                if 'firefox' in wbdrv:
                    main_page = driver.window_handles[0]
                    report_page = driver.window_handles[1]
                    driver.switch_to.window(report_page)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Device Information')]")))
                time.sleep(2)
                logger.info('The Edit Device page was successfully opened')
                driver.save_screenshot(path + 'test_devices_scanned_show_summary_edit_page.png')
            except TimeoutException:
                logger.critical('The edit device page could not be opened, please check the screenshot')
                driver.save_screenshot(path + 'test_devices_scanned_show_summary_edit_issue.png')
                raise Exception
            # Delete the Device Summary - only on firefox
            if 'firefox' in wbdrv:
                try:
                    driver.execute_script("scrollBy(0,+4080);")
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Delete Device')]"))).click()
                    time.sleep(3)
                    logger.info('Delete device summary message popup is shown - ' + driver.switch_to.alert.text)
                    WebDriverWait(driver, 10).until(EC.alert_is_present())
                    driver.switch_to.alert.accept()
                    time.sleep(5)
                    try:
                        WebDriverWait(driver, 5).until(
                            EC.visibility_of_element_located(
                                (By.XPATH, "//*[contains(text(), 'Device Information')]")))
                        logger.critical('The device summary could not be deleted, please check the screenshot!')
                        driver.save_screenshot(path + 'test_devices_scanned_show_summary_delete_issue.png')
                        raise Exception
                    except TimeoutException:
                        logger.info('The Device Summary was successfully deleted!')
                        driver.save_screenshot(path + 'test_devices_scanned_show_summary_delete_successful.png')
                except TimeoutException:
                    logger.critical('The device summary could not be deleted, please check the screenshot!')
                    driver.save_screenshot(path + 'test_devices_scanned_show_summary_delete_issue.png')
                    raise Exception

        # Verify changing user information (time zone and role) and viewing role descriptions
        @staticmethod
        def test_edit_user_page():
            logger.debug('UI test - Edit user page - change time zone and role, view role descriptions')
            login()
            # Change context
            if env == getenv('RI_STAGE_INTEGRATED'):
                time.sleep(0.5)
            else:
                change_context()
            # Go to View and Manage > Users
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Users')]"))).click()
                logger.info('View and Manage - Users page loaded successfully')
            except TimeoutException:
                logger.critical('View and manage Users page did not load!')
                driver.save_screenshot(
                    path + 'test_edit_user_page_view_manage_users_issue.png')
                raise Exception
            # Search user by e-mail, go to edit page
            try:
                user_email = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'gs_email')))
                # Prod. integrated has defined user
                if env == getenv('RI_PROD_INTEGRATED'):
                    user_email.send_keys('riskintelligence42+prod_automation@gmail.com')
                elif env == getenv('RI_STAGE_INTEGRATED'):
                    user_email.send_keys('riskintelligence42+automation@gmail.com')
                elif env == getenv('RI_TEST') or env == getenv('RI_STAGE') or env == getenv('RI_STAGE_EMEA') or env == getenv('RI_PROD)') or env == getenv('RI_PROD_EMEA'):
                    user_email.send_keys('riskintelligence42+ri_test_user@gmail.com')
                time.sleep(1)
                actions = ActionChains(driver)
                actions.send_keys(Keys.ENTER).perform()
                time.sleep(3)
                user = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'RI Automation Test User')]")))
                actions = ActionChains(driver)
                actions.double_click(user).perform()
                time.sleep(1)
                # Switch to a new tab to edit the user
                user_page = driver.window_handles[1]
                driver.switch_to.window(user_page)
                # Select a new role and time zone
                timezone = Select(WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.ID, "user_time_zone"))))
                timezone.select_by_value('Hawaii')
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'ReadOnly')]"))).click()
                driver.save_screenshot(path + 'test_edit_user_page_changes_done.png')
                logger.info('Time zone and role changed for the user, checking role descriptions')
                # View role descriptions
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Show Role Descriptions')]"))).click()
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'InvoiceAdmin:')]")))
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'MarketingAdmin')]")))
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'User:')]")))
                driver.save_screenshot(path + 'test_edit_user_page_roles_description_1.png')
                driver.execute_script("scrollBy(0,+700);")
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'ReadOnly:')]")))
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'SiteAdmin:')]")))
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'OrgAdmin:')]")))
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'DomainAdmin:')]")))
                driver.save_screenshot(path + 'test_edit_user_page_roles_description_2.png')
                driver.execute_script("scrollBy(0,+700);")
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'ChannelAdmin:')]")))
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'SupportAdmin:')]")))
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'EnterpriseAdmin:')]")))
                logger.info('Roles descriptions are present, screenshots taken')
                driver.save_screenshot(path + 'test_edit_user_page_roles_description_3.png')
                # Save the changes
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//input[@value='Update User']"))).click()
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.CSS_SELECTOR, "#main-panel > div.alert.alert-success")))
                logger.info('The user was successfully updated')
                driver.save_screenshot(path + 'test_edit_user_page_edit_successful.png')
            except TimeoutException:
                logger.critical('Could not update the user, please check the screenshot!')
                driver.save_screenshot(path + 'test_edit_user_page_edit_issue.png')
                raise Exception
            # Now go back and revert the changes so we can re-run the test - for integrated
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                try:
                    user_email = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'gs_email')))
                    if env == getenv('RI_STAGE_INTEGRATED'):
                        user_email.send_keys('riskintelligence42+automation@gmail.com')
                    else:
                        user_email.send_keys('riskintelligence42+prod_automation@gmail.com')
                    time.sleep(1)
                    actions = ActionChains(driver)
                    actions.send_keys(Keys.ENTER).perform()
                    time.sleep(3)
                    user = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'RI Automation Test User')]")))
                    actions = ActionChains(driver)
                    actions.double_click(user).perform()
                    time.sleep(3)
                    user_page_2 = driver.window_handles[2]
                    driver.switch_to.window(user_page_2)
                    timezone = Select(WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.ID, "user_time_zone"))))
                    timezone.select_by_value('Central Time (US & Canada)')
                    WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'ReadOnly')]"))).click()
                    driver.execute_script("scrollBy(0,+1000);")
                    WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH, "//input[@value='Update User']"))).click()
                    WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.CSS_SELECTOR, "#main-panel > div.alert.alert-success")))
                except TimeoutException:
                    logger.critical('Could not revert the user changes, please check the screenshot!')
                    driver.save_screenshot(path + 'test_edit_user_page_revert_changes_issue.png')
                    raise Exception

        # Verify changing the organization address / branding - dependency on the create and delete organization tests
        @staticmethod
        def test_edit_organization_address_and_branding():
            logger.debug('UI test - Edit organization address and branding')
            login()
            # Different steps for integrated env. - skips branding edit
            if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
                change_context()
                # Open Customers, search for existing organization and edit it
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Organizations')]"))).click()
                    logger.info('View and Manage - Organizations page loaded successfully')
                    time.sleep(5)
                except TimeoutException:
                    logger.critical('View and manage Organizations page did not load!')
                    driver.save_screenshot(
                        path + 'test_edit_organization_address_and_branding_view_manage_organization_issue.png')
                    raise Exception
                try:
                    if env == getenv('RI_PROD_INTEGRATED'):
                        org = WebDriverWait(driver, 30).until(
                            EC.visibility_of_element_located(
                                (By.XPATH, "//*[contains(text(), 'Bucharest')]")))
                    else:
                        org = WebDriverWait(driver, 30).until(
                            EC.visibility_of_element_located(
                                (By.XPATH, "//*[contains(text(), 'Customer Conference')]")))
                    actions = ActionChains(driver)
                    actions.double_click(org).perform()
                    time.sleep(2)
                    # Switch to a new tab to edit the organization
                    org_page = driver.window_handles[1]
                    driver.switch_to.window(org_page)
                    logger.info('The existing organization was successfully opened')
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_search_successful.png')
                except TimeoutException:
                    logger.critical('The organization was not found, please check the screenshot!')
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_search_issue.png')
                    raise Exception
                # Edit the organization address
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                    "'Account "
                                                                    "Info')]"))).click()
                    WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH,
                         '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[1]/div[1]/span'))).click()
                    time.sleep(2)
                    org_address = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.NAME, 'address')))
                    org_address.send_keys('Test Street no. 1')
                    org_address2 = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.NAME, 'address2')))
                    org_address2.send_keys('Bloc 2, 6th floor, apartment 39')
                    time.sleep(2)
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_filled_fields.png')
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH,
                                                          '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div['
                                                          '1]/div[2]/div/button'))).click()
                    time.sleep(3)
                    if env == getenv('RI_PROD_INTEGRATED'):
                        WebDriverWait(driver, 30).until(
                            EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Bucharest')]")))
                    else:
                        WebDriverWait(driver, 30).until(
                            EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Customer')]")))
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Test Street no. 1')]")))
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Bloc 2, 6th floor, apartment "
                                       "39')]")))
                    logger.info('The organization address was edited successfully!')
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_saved.png')
                except TimeoutException:
                    logger.critical('Could not edit the organization, please check the screenshot!')
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_issue.png')
                    raise Exception
                # Revert changes for future test runs
                try:
                    WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH,
                         '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[1]/div[1]/span'))).click()
                    org_address = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.NAME, 'address')))
                    org_address.clear()
                    org_address2 = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.NAME, 'address2')))
                    org_address2.clear()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH,
                                                          '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div['
                                                          '1]/div[2]/div/button'))).click()
                    time.sleep(2)
                except TimeoutException:
                    logger.warning('There was an issue trying to revert the changes!')
                    driver.save_screenshot(
                        path + 'test_edit_organization_address_and_branding_revert_changes_issue.png')
                try:
                    WebDriverWait(driver, 3).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Test Street no. 1')]")))
                    logger.warning('Fields were not cleared successfully, issues may arise in next runs!')
                    driver.save_screenshot(
                        path + 'test_edit_organization_address_and_branding_clear_fields_issue.png')
                except TimeoutException:
                    time.sleep(0.5)
            else:
                # Open Customers, search for existing organization and edit it
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Organizations')]"))).click()
                    logger.info('View and Manage - Organizations page loaded successfully')
                    time.sleep(5)
                except TimeoutException:
                    logger.critical('View and manage Organizations page did not load!')
                    driver.save_screenshot(
                        path + 'test_edit_organization_address_and_branding_view_manage_organization_issue.png')
                    raise Exception
                try:
                    org = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'RI Automation Test Organization')]")))
                    actions = ActionChains(driver)
                    actions.double_click(org).perform()
                    # Switch to a new tab to edit the organization
                    org_page = driver.window_handles[1]
                    driver.switch_to.window(org_page)
                    logger.info('The existing organization was successfully opened')
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_search_successful.png')
                except TimeoutException:
                    logger.critical('The organization was not found, please check the screenshot!')
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_search_issue.png')
                    raise Exception
                # Edit the organization address
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                    "'Account "
                                                                    "Info')]"))).click()
                    WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH,
                         '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[1]/div[1]/span'))).click()
                    time.sleep(2)
                    org_address = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.NAME, 'address')))
                    org_address.send_keys('Test Street no. 1')
                    org_address2 = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.NAME, 'address2')))
                    org_address2.send_keys('Bloc 2, 6th floor, apartment 39')
                    time.sleep(2)
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_filled_fields.png')
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH,
                                                          '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div['
                                                          '1]/div[2]/div/button'))).click()
                    time.sleep(3)
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI "
                                                                    "Automation Test "
                                                                    "Organization (edited)')]")))
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Test Street no. 1')]")))
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Bloc 2, 6th floor, apartment "
                                       "39')]")))
                    logger.info('The organization address was edited successfully!')
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_saved.png')
                except TimeoutException:
                    logger.critical('Could not edit the organization, please check the screenshot!')
                    driver.save_screenshot(path + 'test_edit_organization_address_and_branding_issue.png')
                    raise Exception
                # Edit the organization branding
                logger.debug('Proceeding with the test - edit organization branding')
                try:
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH,
                             '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[2]/div[1]/span'))).click()
                    time.sleep(5)
                    # Edit the organization Front Matter
                    org_branding_front_matter = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'front-matter')))
                    org_branding_front_matter.send_keys(
                        "<head><script>alert('Promotional Content')Here is also a script</script></head>"
                        "\n<strong>Promotional Content Bold</strong>"
                        "\n<p>This is normal text <b>and this is bold text</b>.</p>"
                        "\n<br>\n<p>Above should be a breaking line </p>"
                        "\n<h1>Header 1</h1>"
                        "\n<h2>Header 2</h2>"
                        "\n<h3>Header 3</h3>"
                        "\n<h4>Header 4</h4>"
                        "\n<a href='http://testing.iscanonline.com'>Promotional Content Link</a>"
                        "\n<img src='https://www.w3schools.com/images/lamp.jpg' alt='Lamp' width='32' height='32'>"
                        "\n<table>"
                        "\n<tr>"
                        "\n<th>Test Column 1</th>"
                        "\n<th>Test Column 2</th>"
                        "\n</tr>"
                        "\n<tr>"
                        "\n<td>Test Row 1 Cell 1</td>"
                        "\n<td>Test Row 1 Cell 2</td>"
                        "\n</tr>"
                        "\n</table>")
                    time.sleep(3)
                    driver.save_screenshot(path + 'test_edit_organization_branding_front_matter_filled_fields.png')
                    driver.execute_script("scrollBy(0,+500);")
                    # Edit the organization Back Matter
                    org_branding_back_matter = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'back-matter')))
                    org_branding_back_matter.send_keys(
                        "<head><script>alert('Promotional Content')Here is also a script</script></head>"
                        "\n<strong>Promotional Content Bold</strong>"
                        "\n<p>This is normal text <b>and this is bold text</b>.</p>"
                        "\n<br>\n<p>Above should be a breaking line </p>"
                        "\n<h1>Header 1</h1>"
                        "\n<h2>Header 2</h2>"
                        "\n<h3>Header 3</h3>"
                        "\n<h4>Header 4</h4>"
                        "\n<a href='http://testing.iscanonline.com'>Promotional Content Link</a>"
                        "\n<img src='https://www.w3schools.com/images/lamp.jpg' alt='Lamp' width='32' height='32'>"
                        "\n<table>"
                        "\n<tr>"
                        "\n<th>Test Column 1</th>"
                        "\n<th>Test Column 2</th>"
                        "\n</tr>"
                        "\n<tr>"
                        "\n<td>Test Row 1 Cell 1</td>"
                        "\n<td>Test Row 1 Cell 2</td>"
                        "\n</tr>"
                        "\n</table>")
                    time.sleep(3)
                    driver.save_screenshot(path + 'test_edit_organization_branding_back_matter_filled_fields.png')
                    driver.execute_script("scrollBy(0,+500);")
                    # Edit the organization Promotional Content
                    org_branding_promo_matter = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'promo-matter')))
                    org_branding_promo_matter.send_keys(
                        "<head><script>alert('Promotional Content')Here is also a script</script></head>"
                        "\n<strong>Promotional Content Bold</strong>"
                        "\n<p>This is normal text <b>and this is bold text</b>.</p>"
                        "\n<br>\n<p>Above should be a breaking line </p>"
                        "\n<h1>Header 1</h1>"
                        "\n<h2>Header 2</h2>"
                        "\n<h3>Header 3</h3>"
                        "\n<h4>Header 4</h4>"
                        "\n<a href='http://testing.iscanonline.com'>Promotional Content Link</a>"
                        "\n<img src='https://www.w3schools.com/images/lamp.jpg' alt='Lamp' width='32' height='32'>"
                        "\n<table>"
                        "\n<tr>"
                        "\n<th>Test Column 1</th>"
                        "\n<th>Test Column 2</th>"
                        "\n</tr>"
                        "\n<tr>"
                        "\n<td>Test Row 1 Cell 1</td>"
                        "\n<td>Test Row 1 Cell 2</td>"
                        "\n</tr>"
                        "\n</table>")
                    time.sleep(3)
                    driver.save_screenshot(path + 'test_edit_organization_branding_promo_matter_filled_fields.png')
                    driver.execute_script("scrollBy(0,+500);")
                    # Edit the organization Sign In Customization
                    org_branding_signin_content = WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located((By.ID, 'signin-content')))
                    org_branding_signin_content.send_keys(
                        "<head><script>alert('Promotional Content')Here is also a script</script></head>"
                        "\n<strong>Promotional Content Bold</strong>"
                        "\n<p>This is normal text <b>and this is bold text</b>.</p>"
                        "\n<br>\n<p>Above should be a breaking line </p>"
                        "\n<h1>Header 1</h1>"
                        "\n<h2>Header 2</h2>"
                        "\n<h3>Header 3</h3>"
                        "\n<h4>Header 4</h4>"
                        "\n<a href='http://testing.iscanonline.com'>Promotional Content Link</a>"
                        "\n<img src='https://www.w3schools.com/images/lamp.jpg' alt='Lamp' width='32' height='32'>"
                        "\n<table>"
                        "\n<tr>"
                        "\n<th>Test Column 1</th>"
                        "\n<th>Test Column 2</th>"
                        "\n</tr>"
                        "\n<tr>"
                        "\n<td>Test Row 1 Cell 1</td>"
                        "\n<td>Test Row 1 Cell 2</td>"
                        "\n</tr>"
                        "\n</table>")
                    time.sleep(3)
                    driver.save_screenshot(
                        path + 'test_edit_organization_branding_signin-content_filled_fields.png')
                    # Save
                    WebDriverWait(driver, 30).until(
                        EC.visibility_of_element_located(
                            (By.XPATH,
                             '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[2]/div[2]/div'))).click()
                    time.sleep(5)
                    driver.save_screenshot(path + 'test_edit_organization_branding_save_successful.png')
                    logger.info('The branding was successfully edited')
                except TimeoutException:
                    logger.critical('Could not edit the organization branding, please check the screenshot!')
                    driver.save_screenshot(path + 'test_edit_organization_branding_save_issue.png')
                    raise Exception

        # Verify changing the domain address / branding - dependency on the create and delete domain tests
        @staticmethod
        def test_edit_domain_address_and_branding():
            logger.debug('UI test - Edit domain address')
            login()
            # Open Customers, search for existing domain and edit it
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Domains')]"))).click()
                logger.info('View and Manage - Domains page loaded successfully')
                time.sleep(5)
            except TimeoutException:
                logger.critical('View and manage Domains page did not load!')
                driver.save_screenshot(
                    path + 'test_edit_domain_address_view_manage_organization_issue.png')
                raise Exception
            try:
                domain_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, "gs_name")))
                domain_name.click()
                domain_name.send_keys('RI Automation Test Domain')
                time.sleep(1)
                actions = ActionChains(driver)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//td[@aria-describedby='table_domain_grid_name']"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="pager_domain_grid_left"]/table/tbody/tr/td[2]/div'))).click()
                # Switch to a new tab to edit the domain
                user_page = driver.window_handles[1]
                driver.switch_to.window(user_page)
                logger.info('The existing domain was successfully opened')
            except TimeoutException:
                logger.critical('The domain was no found. Please check the screenshot')
                driver.save_screenshot(path + 'test_edit_domain_address_search_issue.png')
                raise Exception
            # Edit the domain address
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/fieldset[1]/div[2]/a'))).click()
            except TimeoutException:
                logger.critical('Could not edit the domain. Please check the screenshot!')
                driver.save_screenshot(path + 'test_edit_domain_address_edit_issue')
                raise Exception
            time.sleep(3)
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                "'Account "
                                                                "Info')]"))).click()
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH,
                     '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[1]/div[1]/span'))).click()
                time.sleep(5)
                org_address = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.NAME, 'address')))
                org_address.send_keys('Test Street no. 1')
                org_address2 = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.NAME, 'address2')))
                org_address2.send_keys('Bloc 2, 6th floor, apartment 39')
                time.sleep(2)
                driver.save_screenshot(path + 'test_edit_domain_address_filled_fields.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH,
                                                      '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div['
                                                      '1]/div[2]/div/button'))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'RI "
                                                                "Automation Test "
                                                                "Domain (edited)')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Test Street no. 1')]")))
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Bloc 2, 6th floor, apartment "
                                   "39')]")))
                logger.info('The domain was edited successfully!')
                driver.save_screenshot(path + 'test_edit_domain_address_saved.png')
            except TimeoutException:
                logger.warning('Could not edit the domain address, please check the screenshot!')
                driver.save_screenshot(path + 'test_edit_domain_address_issue.png')
                raise Exception
            # Edit the domain branding
            logger.debug('Proceeding with the test - edit domain branding')
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[2]/div[1]/span'))).click()
                time.sleep(5)
                # Edit the organization Front Matter
                dom_branding_front_matter = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'front-matter')))
                dom_branding_front_matter.send_keys(
                    "<head><script>alert('Promotional Content')Here is also a script</script></head>"
                    "\n<strong>Promotional Content Bold</strong>"
                    "\n<p>This is normal text <b>and this is bold text</b>.</p>"
                    "\n<br>\n<p>Above should be a breaking line </p>"
                    "\n<h1>Header 1</h1>"
                    "\n<h2>Header 2</h2>"
                    "\n<h3>Header 3</h3>"
                    "\n<h4>Header 4</h4>"
                    "\n<a href='http://testing.iscanonline.com'>Promotional Content Link</a>"
                    "\n<img src='https://www.w3schools.com/images/lamp.jpg' alt='Lamp' width='32' height='32'>"
                    "\n<table>"
                    "\n<tr>"
                    "\n<th>Test Column 1</th>"
                    "\n<th>Test Column 2</th>"
                    "\n</tr>"
                    "\n<tr>"
                    "\n<td>Test Row 1 Cell 1</td>"
                    "\n<td>Test Row 1 Cell 2</td>"
                    "\n</tr>"
                    "\n</table>")
                time.sleep(3)
                driver.save_screenshot(path + 'test_edit_domain_branding_front_matter_filled_fields.png')
                driver.execute_script("scrollBy(0,+500);")
                # Edit the organization Back Matter
                dom_branding_back_matter = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'back-matter')))
                dom_branding_back_matter.send_keys(
                    "<head><script>alert('Promotional Content')Here is also a script</script></head>"
                    "\n<strong>Promotional Content Bold</strong>"
                    "\n<p>This is normal text <b>and this is bold text</b>.</p>"
                    "\n<br>\n<p>Above should be a breaking line </p>"
                    "\n<h1>Header 1</h1>"
                    "\n<h2>Header 2</h2>"
                    "\n<h3>Header 3</h3>"
                    "\n<h4>Header 4</h4>"
                    "\n<a href='http://testing.iscanonline.com'>Promotional Content Link</a>"
                    "\n<img src='https://www.w3schools.com/images/lamp.jpg' alt='Lamp' width='32' height='32'>"
                    "\n<table>"
                    "\n<tr>"
                    "\n<th>Test Column 1</th>"
                    "\n<th>Test Column 2</th>"
                    "\n</tr>"
                    "\n<tr>"
                    "\n<td>Test Row 1 Cell 1</td>"
                    "\n<td>Test Row 1 Cell 2</td>"
                    "\n</tr>"
                    "\n</table>")
                time.sleep(3)
                driver.save_screenshot(path + 'test_edit_domain_branding_back_matter_filled_fields.png')
                driver.execute_script("scrollBy(0,+500);")
                # Edit the organization Promotional Content
                dom_branding_promo_matter = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'promo-matter')))
                dom_branding_promo_matter.send_keys(
                    "<head><script>alert('Promotional Content')Here is also a script</script></head>"
                    "\n<strong>Promotional Content Bold</strong>"
                    "\n<p>This is normal text <b>and this is bold text</b>.</p>"
                    "\n<br>\n<p>Above should be a breaking line </p>"
                    "\n<h1>Header 1</h1>"
                    "\n<h2>Header 2</h2>"
                    "\n<h3>Header 3</h3>"
                    "\n<h4>Header 4</h4>"
                    "\n<a href='http://testing.iscanonline.com'>Promotional Content Link</a>"
                    "\n<img src='https://www.w3schools.com/images/lamp.jpg' alt='Lamp' width='32' height='32'>"
                    "\n<table>"
                    "\n<tr>"
                    "\n<th>Test Column 1</th>"
                    "\n<th>Test Column 2</th>"
                    "\n</tr>"
                    "\n<tr>"
                    "\n<td>Test Row 1 Cell 1</td>"
                    "\n<td>Test Row 1 Cell 2</td>"
                    "\n</tr>"
                    "\n</table>")
                time.sleep(3)
                driver.save_screenshot(path + 'test_edit_domain_branding_promo_matter_filled_fields.png')
                driver.execute_script("scrollBy(0,+500);")
                # Edit the organization Sign In Customization
                dom_branding_signin_content = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'signin-content')))
                dom_branding_signin_content.send_keys(
                    "<head><script>alert('Promotional Content')Here is also a script</script></head>"
                    "\n<strong>Promotional Content Bold</strong>"
                    "\n<p>This is normal text <b>and this is bold text</b>.</p>"
                    "\n<br>\n<p>Above should be a breaking line </p>"
                    "\n<h1>Header 1</h1>"
                    "\n<h2>Header 2</h2>"
                    "\n<h3>Header 3</h3>"
                    "\n<h4>Header 4</h4>"
                    "\n<a href='http://testing.iscanonline.com'>Promotional Content Link</a>"
                    "\n<img src='https://www.w3schools.com/images/lamp.jpg' alt='Lamp' width='32' height='32'>"
                    "\n<table>"
                    "\n<tr>"
                    "\n<th>Test Column 1</th>"
                    "\n<th>Test Column 2</th>"
                    "\n</tr>"
                    "\n<tr>"
                    "\n<td>Test Row 1 Cell 1</td>"
                    "\n<td>Test Row 1 Cell 2</td>"
                    "\n</tr>"
                    "\n</table>")
                time.sleep(3)
                driver.save_screenshot(path + 'test_edit_domain_branding_signin-content_filled_fields.png')
                # Save
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                time.sleep(5)
                driver.save_screenshot(path + 'test_edit_domain_branding_save_successful.png')
                logger.info('The branding was successfully edited')
            except TimeoutException:
                logger.critical('Could not edit the domain branding, please check the screenshot!')
                driver.save_screenshot(path + 'test_edit_domain_branding_save_issue.png')
                raise Exception

        # Verify that list of scans is populated and can be filtered
        @staticmethod
        def test_filter_scan_key_management():
            logger.debug('UI test - Filter Scan Key Management')
            login()
            # Open View and Manage, Scan Key Management
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'view_manage'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Key Management')]"))).click()
                logger.info('View and Manage - Scan Key Management page loaded successfully')
                time.sleep(5)
            except TimeoutException:
                logger.critical('View and manage - Scan Key Management page did not load!')
                driver.save_screenshot(
                    path + 'test_filter_scan_key_management_page_issue.png')
                raise Exception
            # Filter the scans by short code
            try:
                short_code_filter = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, "gs_short_code")))
                short_code_filter.send_keys(short_code)
                short_code_filter.send_keys(Keys.ENTER)
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Check')]")))
                logger.info('Filtering scans by short code was successful!')
                driver.save_screenshot(path + 'test_filter_scan_key_management_filter_successful.png')
            except TimeoutException:
                logger.critical('Could not filter scan keys, please check the screenshot!')
                driver.save_screenshot(path + 'test_filter_scan_key_management_filter_issue.png')
                raise Exception

        # Check adding / editing / deleting a scan configuration option
        @staticmethod
        def test_add_edit_delete_scan_configuration_option():
            logger.debug('UI test - Add / Edit / Delete Scan Configuration Options')
            login()
            # Open existing domain and organization
            change_context()
            # Open Utilities > Scan Configuration Options
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//a[normalize-space()='Utilities']"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Configuration Options')]"))).click()
                logger.info('Utilities - Scan Configuration Options page loaded successfully')
                driver.save_screenshot(path + 'test_add_edit_delete_scan_configuration_option_page.png')
                time.sleep(3)
            except TimeoutException:
                logger.critical('Utilities - Scan Configuration Options page did not load!')
                driver.save_screenshot(
                    path + 'test_add_edit_delete_scan_configuration_option_page_issue.png')
                raise Exception
            # Add scan configuration option
            try:
                driver.execute_script("scrollBy(0,+2000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//a[normalize-space()='Add Scan Configuration Option']"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Scan Configuration Options')]")))
                key_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "scan_configuration_option_key")))
                key_name.send_keys("upload_crash_dump (copy)")
                description = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "scan_configuration_option_description")))
                description.send_keys(
                    "Copy made by automation test: Allow automatic upload of crash dumps. This can help us resolve "
                    "issues with failing scans.")
                default_value = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "scan_configuration_option_default_value")))
                default_value.send_keys("true")
                validation_regex = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "scan_configuration_option_validation_regex")))
                validation_regex.send_keys("^(true|false)$")
                time.sleep(1)
                driver.save_screenshot(path + "test_add_edit_delete_scan_configuration_option_filled_fields.png")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//input[@name='commit']"))).click()
                time.sleep(5)
                driver.execute_script("scrollBy(0,+2000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'upload_crash_dump (copy)')]")))
                logger.info('Scan configuration option added successfully!')
                driver.save_screenshot(path + "test_add_edit_delete_scan_configuration_option_added_successfully.png")
            except TimeoutException:
                logger.critical('Scan Configuration Option could not be saved!')
                driver.save_screenshot(
                    path + 'test_add_edit_delete_scan_configuration_option_save_issue.png')
                raise Exception
            # Edit scan configuration option - key name
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'upload_crash_dump (copy)')]"))).click()
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                key_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.ID, "scan_configuration_option_key")))
                key_name.send_keys(" (edited)")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//input[@name='commit']"))).click()
                time.sleep(5)
                driver.execute_script("scrollBy(0,+2000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'upload_crash_dump (copy) (edited)')]")))
                logger.info('Scan configuration option was edited successfully!')
                driver.save_screenshot(path + "test_add_edit_delete_scan_configuration_option_edited_successfully.png")
            except TimeoutException:
                logger.critical('Scan Configuration Option could not be edited!')
                driver.save_screenshot(
                    path + 'test_add_edit_delete_scan_configuration_option_edit_issue.png')
            # Delete scan configuration option
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'upload_crash_dump (copy) (edited)')]"))).click()
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                WebDriverWait(driver, 30).until(EC.alert_is_present())
                logger.info('Delete scan configuration option alert shown - ' + driver.switch_to.alert.text)
                driver.switch_to.alert.accept()
                time.sleep(2)
                try:
                    driver.execute_script("scrollBy(0,+2000);")
                    WebDriverWait(driver, 3).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'upload_crash_dump (copy) (edited)')]")))
                    logger.critical('Scan Configuration Option could not be deleted!')
                    driver.save_screenshot(path + 'test_add_edit_delete_scan_configuration_option_delete_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info('Scan configuration option deleted successfully!')
                    driver.save_screenshot(path + "test_add_edit_delete_scan_configuration_option_deleted_successfully.png")
            except TimeoutException:
                logger.critical('Scan Configuration Option could not be deleted!')
                driver.save_screenshot(
                    path + 'test_add_edit_delete_scan_configuration_option_delete_issue.png')
                raise Exception

        # Check adding / deleting a data ruleset with rules
        @staticmethod
        def test_add_delete_data_ruleset():
            logger.debug('UI test - Add / Delete a data ruleset')
            login()
            # Open existing domain and organization
            change_context()
            # Open Utilities > Manage Data Rules
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//a[normalize-space()='Utilities']"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Manage Data Rules')]"))).click()
                logger.info('Utilities - Manage Data Rules page loaded successfully!')
                driver.save_screenshot(path + 'test_add_delete_data_ruleset_manage_data_rules_page.png')
                time.sleep(5)
            except TimeoutException:
                logger.critical('Utilities - Manage Data Rules page did not load!')
                driver.save_screenshot(
                    path + 'test_add_delete_data_ruleset_manage_data_rules_page_issue.png')
                raise Exception
            # Add a new data ruleset with rules
            try:
                driver.execute_script("scrollBy(0,+10000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//button[normalize-space()='Create New Rule']"))).click()
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Editing Rule')]")))
                ruleset_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//input[@type='text']")))
                ruleset_name.send_keys("Automation Check")
                # Add regular expression
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//div[@iscan-rules-editor='scanCannedRegex.file_rules']//button[@class='pull-right btn "
                         "btn-xs btn-info'][normalize-space()='add']"))).click()
                regular_expression = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//input[@class='input-sm form-control ng-isolate-scope ng-pristine ng-invalid "
                         "ng-invalid-required ng-valid-regex-validate']")))
                regular_expression.send_keys(
                    "\b(?:(?:[Tt][Ee][Ll][Ee])?[Pp][Hh][Oo][Nn][Ee]|[Cc][Ee][Ll][Ll]|[Mm][Oo][Bb][Ii][Ll](?:[Ee]|["
                    "Tt][Ee][Ll][Ee][Ff][Oo][Nn])|[Tt][Ee][Ll][Ee][Ff][Oo][Nn]|[Hh][Aa][Nn][Dd][Yy]|[Ff]ax)(?:\n|\r|[ "
                    "]?[#:-]|[ ][Nn][Uu][Mm][Bb][Ee][Rr][Ss]?|[Nn][Uu][Mm][Mm][Ee][Rr][Ss]?|[ ][Nn][Uu][Mm][:.]|[ ]["
                    "Nn][Oo][:.])")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//button[@ng-disabled='rule.invalid || rule.pending']"))).click()
                driver.execute_script("scrollBy(0,+500);")
                # Add rule
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//div[@iscan-rules-editor='scanCannedRegex.rules']//button[@class='pull-right btn btn-xs "
                         "btn-info'][normalize-space()='add']"))).click()
                rule_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//input[@class='input-sm form-control ng-pristine ng-valid']")))
                rule_name.send_keys("US Phone #")
                rule_regular_expression = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//input[@class='input-sm form-control ng-isolate-scope ng-pristine ng-invalid "
                         "ng-invalid-required ng-valid-regex-validate']")))
                rule_regular_expression.send_keys(
                    "(?:\+?1?(?:(?:[2-9][0-9]{2}|\([2-9][0-9]{2}\)))?[2-9][0-9]{2}[0-9]{4}|(?:1-|\+1[ ])?(?:(?:[2-9]["
                    "0-9]{2}|\([2-9][0-9]{2}\))[- ]?)?[2-9][0-9]{2}-[0-9]{4}|(?:1[ ])?(?:(?:[2-9][0-9]{2}|\([2-9]["
                    "0-9]{2}\))[ ])?[2-9][0-9]{2}[ ][0-9]{4}|(?:\+?1\.)?(?:(?:[2-9][0-9]{2}|\([2-9][0-9]{2}\))\.)?["
                    "2-9][0-9]{2}\.[0-9]{4})(?:[ ](?:[Ee]xt|x)[-\.:]?[ ][0-9]{1,6})?")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         "//tr[@ng-class='{danger: rule.invalid && !rule.editing}']//button[@class='btn btn-default "
                         "btn-xs'][normalize-space()='done']"))).click()
                time.sleep(1)
                driver.save_screenshot(path + "test_add_delete_manage_data_rules_filled_fields.png")
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/div[2]/div[2]/form/div/button[1]'))).click()
                time.sleep(3)
                driver.execute_script("scrollBy(0,+10000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Check')]")))
                logger.info('Data ruleset added successfully!')
                driver.save_screenshot(path + "test_add_delete_data_ruleset_save_successful.png")
            except TimeoutException:
                logger.critical('Data ruleset could not be created!')
                driver.save_screenshot(
                    path + 'test_add_delete_data_ruleset_save_issue.png')
                raise Exception
            # Edit the newly created data ruleset
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Check')]"))).click()
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                driver.execute_script("scrollBy(0,+500);")
                ruleset_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//input[@ng-model='scanCannedRegex.name']")))
                ruleset_name.send_keys(" (edited)")
                driver.execute_script("scrollBy(0,+500);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//button[normalize-space()='Save']"))).click()
                time.sleep(5)
                driver.execute_script("scrollBy(0,+10000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Check (edited)')]")))
                logger.info('Data ruleset was edited successfully!')
                driver.save_screenshot(path + "test_add_delete_data_ruleset_edit_successful.png")
            except TimeoutException:
                logger.critical('Newly created data ruleset could not be edited!')
                driver.save_screenshot(
                    path + 'test_add_delete_data_ruleset_edit_issue.png')
            # Delete edited data ruleset
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Check (edited)')]"))).click()
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                WebDriverWait(driver, 30).until(EC.alert_is_present())
                logger.info('Delete data ruleset alert is shown - ' + driver.switch_to.alert.text)
                driver.switch_to.alert.accept()
                time.sleep(3)
                try:
                    driver.execute_script("scrollBy(0,+10000);")
                    WebDriverWait(driver, 3).until(
                        EC.visibility_of_element_located(
                            (By.XPATH, "//*[contains(text(), 'Automation Check (edited)')]")))
                    logger.critical('Data ruleset was not deleted, please check the screenshot!')
                    driver.save_screenshot(path + 'test_add_delete_data_ruleset_delete_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info('Data ruleset deleted successfully!')
                    driver.save_screenshot(path + "test_add_delete_data_ruleset_delete_successful.png")
            except TimeoutException:
                logger.critical('Data ruleset could not be deleted')
                driver.save_screenshot(
                    path + 'test_add_delete_data_ruleset_delete_issue.png')
                raise Exception

        # Check creating / editing / deleting a new report along with other checks
        @staticmethod
        def test_report():
            logger.debug('UI test - Create / edit / delete new report, generate data, verify email being sent')
            login()
            # Search for existing Organization and Domain and change context
            change_context()
            # Open Reports
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'reports'))).click()
                time.sleep(1)
                driver.execute_script("scrollBy(0,+10000);")
                time.sleep(1)
                # Failsafe check that report doesn't already exist to avoid issues
                try:
                    driver.execute_script("scrollBy(0,+3000);")
                    report = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                    logger.info('Report already exist, will delete it before proceeding with the test')
                    if 'chrome' in wbdrv:
                        actions = ActionChains(driver)
                        actions.move_to_element_with_offset(report, 50, 50).click()
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.ENTER)
                        time.sleep(1)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ENTER)
                        actions.perform()
                    elif 'firefox' in wbdrv:
                        actions = ActionChains(driver)
                        actions.move_to_element_with_offset(report, 40, 40).click()
                        time.sleep(1)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.TAB)
                        actions.send_keys(Keys.ENTER)
                        time.sleep(1)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ARROW_DOWN)
                        actions.send_keys(Keys.ENTER)
                        actions.perform()
                    time.sleep(3)
                    try:
                        WebDriverWait(driver, 10).until(EC.alert_is_present())
                        driver.switch_to.alert.accept()
                    except selenium.common.exceptions.NoAlertPresentException:
                        time.sleep(1)
                except TimeoutException:
                    time.sleep(1)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), 'Create New Report')]")))
                logger.info('Reports page loaded successfully')
                time.sleep(3)
            except TimeoutException:
                logger.warning('The reports page did not load!')
                driver.save_screenshot(path + 'test_report_reports_page_issue.png')
            try:
                driver.execute_script("scrollBy(0,200000);")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Create New Report')]"))).click()
                logger.info('The Create Report page opened successfully')
                time.sleep(5)
            except TimeoutException:
                logger.critical('The Create Report page did not load or there was an issue, aborting test!')
                driver.save_screenshot(path + 'reports_page_issue.png')
                raise Exception
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Security and Data Breach Reports')]"))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                time.sleep(3)
                driver.execute_script("scrollBy(0,500);")
                WebDriverWait(driver, 60).until(EC.visibility_of_element_located(
                    (By.XPATH,
                     '//*[@id="main-panel"]/div[2]/div[3]/ng-form/div[5]/div/div[1]/div/div/div[7]/div'))).click()
                driver.execute_script("scrollBy(0,1080);")
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                # Add report name
                report_name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH,
                         '//*[@id="main-panel"]/div[2]/div[3]/ng-form/div[5]/div/div[1]/div/div[1]/div/input')))
                report_name.send_keys('Automation Test Report')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Next')]"))).click()
                logger.info('The report was completed successfully!')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Save')]"))).click()
                time.sleep(3)
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.ID, "main-panel"))).click()
                driver.execute_script("scrollBy(0,200000);")
            except TimeoutException:
                logger.critical('There was an issue completing the report. Please check the screenshot!')
                driver.save_screenshot(path + 'test_report_complete_issue.png')
                raise Exception
            try:
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                logger.info('The report was saved successfully!')
                driver.save_screenshot(path + 'test_report_successful.png')
            except TimeoutException:
                logger.critical('There was an issue saving the report. Please check the screenshot')
                driver.save_screenshot(path + 'test_report_save_issue.png')
                raise Exception
            main = driver.window_handles[0]
            # Edit the report recipients
            report = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
            if 'chrome' in wbdrv:
                actions = ActionChains(driver)
                actions.move_to_element_with_offset(report, 50, 50).click()
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                time.sleep(1)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ENTER)
                actions.perform()
            elif 'firefox' in wbdrv:
                actions = ActionChains(driver)
                actions.move_to_element_with_offset(report, 40, 40).click()
                time.sleep(1)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                time.sleep(1)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ENTER)
                actions.perform()
            try:
                actions = ActionChains(driver)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys('ritestinbox@mailinator.com')
                time.sleep(1)
                actions.send_keys(Keys.ENTER)
                actions.perform()
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH,
                     "//div[@class='modal modal-large in']//button[@class='btn btn-default btn-sm pull-right']["
                     "normalize-space()='Save']"))).click()
                driver.save_screenshot(path + 'test_report_recipients_added.png')
            except TimeoutException:
                logger.critical('The email could not be added in the recipient list')
                driver.save_screenshot(path + 'test_report_recipients_issue.png')
                raise Exception
            try:
                logger.debug('Proceeding with generating report data')
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report')]"))).click()
                time.sleep(3)
                # Switch to new tab to verify report has been generated
                new_tab = driver.window_handles[1]
                driver.switch_to.window(new_tab)
                WebDriverWait(driver, 120).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                time.sleep(5)
                driver.save_screenshot(path + 'test_report_data_generated.png')
                logger.info('The report data has been generated')
            except TimeoutException:
                logger.critical('The report data could not be generated! Please check the attached screenshot!')
                driver.save_screenshot(path + 'test_report_data_generation_issue.png')
                # Need to delete the stuck report so it doesn't interfere with future runs
                driver.switch_to.window(main)
                report = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                if 'chrome' in wbdrv:
                    actions = ActionChains(driver)
                    actions.move_to_element_with_offset(report, 50, 50).click()
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                elif 'firefox' in wbdrv:
                    actions = ActionChains(driver)
                    actions.move_to_element_with_offset(report, 40, 40).click()
                    time.sleep(1)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                WebDriverWait(driver, 10).until(EC.alert_is_present())
                driver.switch_to.alert.accept()
                raise Exception
            # Edit the report name
            driver.switch_to.window(main)
            time.sleep(1)
            driver.refresh()
            time.sleep(5)
            driver.execute_script("scrollBy(0,+10000);")
            time.sleep(1)
            report = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
            if 'chrome' in wbdrv:
                actions = ActionChains(driver)
                actions.move_to_element_with_offset(report, 50, 50).click()
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                time.sleep(1)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ENTER)
                actions.perform()
            elif 'firefox' in wbdrv:
                actions = ActionChains(driver)
                actions.move_to_element_with_offset(report, 40, 40).click()
                time.sleep(1)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.TAB)
                actions.send_keys(Keys.ENTER)
                time.sleep(1)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ARROW_DOWN)
                actions.send_keys(Keys.ENTER)
                actions.perform()
            try:
                report_name = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//div[@class='modal modal-large in']//input[@name='name']")))
                report_name.send_keys(' (edited)')
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH,
                     "//div[@class='modal modal-large in']//button[@class='btn btn-default btn-sm pull-right']["
                     "normalize-space()='Save']"))).click()
                time.sleep(3)
                driver.execute_script("scrollBy(0,+10000);")
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report (edited)')]")))
                logger.info('The report name was edited successfully!')
                driver.save_screenshot(path + 'test_report_edit_successful.png')
            except TimeoutException:
                logger.critical('The report name could not be changed, please check the screenshot!')
                driver.save_screenshot(path + 'test_report_rename_issue.png')
            # Delete the report to prevent clutter
            try:
                time.sleep(1)
                driver.refresh()
                time.sleep(5)
                driver.execute_script("scrollBy(0,+10000);")
                time.sleep(1)
                report = WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH, "//*[contains(text(), 'Automation Test Report (edited)')]")))
                if 'chrome' in wbdrv:
                    actions = ActionChains(driver)
                    actions.move_to_element_with_offset(report, 50, 50).click()
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                elif 'firefox' in wbdrv:
                    actions = ActionChains(driver)
                    actions.move_to_element_with_offset(report, 40, 40).click()
                    time.sleep(1)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.TAB)
                    actions.send_keys(Keys.ENTER)
                    time.sleep(1)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ARROW_DOWN)
                    actions.send_keys(Keys.ENTER)
                    actions.perform()
                WebDriverWait(driver, 10).until(EC.alert_is_present())
                logger.info('Delete report message popup is shown - ' + driver.switch_to.alert.text)
                WebDriverWait(driver, 10).until(EC.alert_is_present()).accept()
                time.sleep(5)
                driver.execute_script("scrollBy(0,+10000);")
                time.sleep(1)
                try:
                    WebDriverWait(driver, 5).until(EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Automation Test Report')]")))
                    logger.critical('The report was not deleted!')
                    driver.save_screenshot(path + 'test_report_delete_issue.png')
                    raise Exception
                except TimeoutException:
                    logger.info('The report was deleted successfully!')
                    driver.save_screenshot(path + 'test_report_deleted_successfully.png')
            except TimeoutException:
                logger.critical(
                    'There was an issue deleting the report!')
                driver.save_screenshot(path + 'test_report_delete_issue.png')
                raise Exception
            # Check that the report was sent via email - TBA
            """try:
                driver.switch_to.new_window()
                driver.get('https://www.mailinator.com/v4/public/inboxes.jsp?to=ritestinbox')"""

        # Check that the billing report is generated
        @staticmethod
        def test_generate_billing_report():
            logger.debug('UI test - Generate billing report')
            login()
            change_context()
            # Open Utilities > Billing Reports
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//a[normalize-space()='Utilities']"))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//*[contains(text(), 'Billing Reports')]"))).click()
                logger.info('Utilities - Billing Reports page loaded successfully')
                driver.save_screenshot(path + 'test_generate_billing_report_page_loaded.png')
                time.sleep(5)
            except TimeoutException:
                logger.critical('Utilities - Billing Reports page did not load!')
                driver.save_screenshot(
                    path + 'test_generate_billing_report_page_issue.png')
                raise Exception
            # Cleanup folder of previous downloads
            for filename in glob(r"C:\Jenkins\temp\*.csv"):
                os.remove(filename)
            # Open latest Standalone Usage for Month billing report
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, '//*[@id="main-panel"]/table/tbody/tr[2]/td[2]/div[1]/a'))).click()
                logger.info("Waiting for downloads")
                while any([filename.endswith(".crdownload") for filename in
                           os.listdir("/Downloads")]):
                    time.sleep(2)
                logger.info("The billing report was successfully downloaded")
            except TimeoutException:
                logger.critical('The Standalone Usage for Month report could not be downloaded')
                driver.save_screenshot(path + 'test_generate_billing_report_download_issue.png')

        @staticmethod
        def test_user_settings_change_name_timezone():
            logger.debug('UI test - User settings > Change name/change timezone')
            login()
            # Go to My Account > User settings
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'myAccount'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//a[normalize-space()='User Settings']"))).click()
                logger.info('The user settings page was opened successfully')
            except TimeoutException:
                logger.warning('The user settings page could not be opened!')
                driver.save_screenshot(path + 'test_user_settings_change_name_timezone_page_issue.png')
            # Change name and timezone
            try:
                name = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'user_fullname')))
                name.send_keys(" (edited)")
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'user_time_zone'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, '//*[@id="user_time_zone"]/option[14]'))).click()
                time.sleep(5)
                # Save
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//input[@name='commit']"))).click()
                time.sleep(5)
                logger.info('The user was edited successfully')
            except TimeoutException:
                logger.warning('The user settings page could not be opened!')
                driver.save_screenshot(path + 'test_user_settings_change_name_timezone_edit_issue.png')

        @staticmethod
        def test_user_account_change_org_address():
            logger.debug('UI test - User account > Change organisation name')
            login()
            # Go to My Account > User settings
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.ID, 'myAccount'))).click()
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, '//*[@id="submenu-#lnhUserAccount"]/li[2]/a'))).click()
                logger.info('The user account page was opened successfully')
            except TimeoutException:
                logger.warning('The user account page could not be opened!')
                driver.save_screenshot(path + 'test_user_account_change_org_address_page_issue.png')
            # Edit organization name and address
            try:
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.XPATH, "//*[contains(text(), "
                                                                "'Account "
                                                                "Info')]"))).click()
                WebDriverWait(driver, 30).until(EC.visibility_of_element_located(
                    (By.XPATH,
                     '//*[@id="main-panel"]/div[2]/div[2]/div[1]/fieldset/div[1]/div[1]/span'))).click()
                time.sleep(5)
                org_addr = WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located((By.NAME, 'address')))
                org_addr.send_keys(' (edited)')
                time.sleep(3)
                driver.save_screenshot(path + 'test_user_account_change_org_address_filled_fields.png')
                WebDriverWait(driver, 30).until(
                    EC.visibility_of_element_located(
                        (By.XPATH, "//button[@class='btn btn-default btn-xs pull-right ng-binding']"))).click()
                time.sleep(3)
                logger.info('The organization was edited successfully!')
                driver.save_screenshot(path + 'test_user_account_change_org_address_organization_saved.png')
            except TimeoutException:
                logger.warning('Could not edit the organization, please check the screenshot!')
                driver.save_screenshot(path + 'test_user_account_change_org_address_edit_issue.png')

        def tearDown(self):
            driver.quit()

    # Create a test suite and add tests to it, need to customize for integrated env.
    test_suite = unittest.TestSuite()
    if env == getenv('RI_PROD_INTEGRATED') or env == getenv('RI_STAGE_INTEGRATED'):
        test_suite.addTest(Basic_Checks('test_login_checks'))
        test_suite.addTest(Basic_Checks('test_basic_page_checks'))
        test_suite.addTest(Basic_Checks('test_create_delete_scan_config'))
        test_suite.addTest(Basic_Checks('test_change_context'))
        test_suite.addTest(Basic_Checks('test_integrated_sso'))
        test_suite.addTest(Basic_Checks('test_add_rename_delete_widget'))
        test_suite.addTest(Basic_Checks('test_scan_result_view_delete'))
        test_suite.addTest(Basic_Checks('test_scan_results_add_remove_column'))
        test_suite.addTest(Basic_Checks('test_edit_organization_address_and_branding'))
        test_suite.addTest(Basic_Checks('test_add_edit_delete_scan_configuration_option'))
        test_suite.addTest(Basic_Checks('test_add_delete_data_ruleset'))
        # tests that we can't run yet on staging
        if env == getenv('RI_STAGE_INTEGRATED'):
            time.sleep(1)
        else:
            test_suite.addTest(Basic_Checks('test_integrated_report'))
    else:
        test_suite.addTest(Basic_Checks('test_login_checks'))
        test_suite.addTest(Basic_Checks('test_basic_page_checks'))
        test_suite.addTest(Basic_Checks('test_scan_device_added'))
        test_suite.addTest(Basic_Checks('test_create_delete_scan_config'))
        test_suite.addTest(Basic_Checks('test_change_context'))
        test_suite.addTest(Basic_Checks('test_create_edit_user'))
        test_suite.addTest(Basic_Checks('test_edit_user_page'))
        test_suite.addTest(Basic_Checks('test_delete_user'))
        test_suite.addTest(Basic_Checks('test_create_edit_organization'))
        test_suite.addTest(Basic_Checks('test_verify_default_scans'))
        test_suite.addTest(Basic_Checks('test_edit_organization_address_and_branding'))
        test_suite.addTest(Basic_Checks('test_delete_organization'))
        test_suite.addTest(Basic_Checks('test_create_edit_domain'))
        test_suite.addTest(Basic_Checks('test_edit_domain_address_and_branding'))
        test_suite.addTest(Basic_Checks('test_delete_domain'))
        test_suite.addTest(Basic_Checks('test_add_rename_delete_widget'))
        test_suite.addTest(Basic_Checks('test_scan_delivery_methods'))
        test_suite.addTest(Basic_Checks('test_scan_results_add_remove_column'))
        test_suite.addTest(Basic_Checks('test_scan_result_view_delete'))
        test_suite.addTest(Basic_Checks('test_devices_scanned_add_remove_column'))
        test_suite.addTest(Basic_Checks('test_devices_scanned_show_summary'))
        test_suite.addTest(Basic_Checks('test_filter_scan_key_management'))
        test_suite.addTest(Basic_Checks('test_add_edit_delete_scan_configuration_option'))
        test_suite.addTest(Basic_Checks('test_add_delete_data_ruleset'))
        test_suite.addTest(Basic_Checks('test_report'))
        test_suite.addTest(Basic_Checks('test_generate_billing_report'))
        test_suite.addTest(Basic_Checks('test_user_settings_change_name_timezone'))
        test_suite.addTest(Basic_Checks('test_user_account_change_org_address'))

    # Run suite
    output = open(path + 'Results.xml', 'wb')
    runner = xmlrunner.XMLTestRunner(output=output, verbosity=2, failfast=True)
    runner.run(test_suite)

