from os.path import dirname, join, abspath
import sys

sys.path.insert(0, abspath(join(dirname(__file__), '..')))
from Tests.UI_tests import *

# Variables for this test config
dotenv.load_dotenv(verbose=True)
wbdrv = 'chrome'
env = getenv('RI_TEST')
path = '../test-reports/' + 'Test Run ' + time.strftime('%d %b %Y %H') + ' - Chrome - '

# Run the whole test suite
ui_tests(env, path, wbdrv)
