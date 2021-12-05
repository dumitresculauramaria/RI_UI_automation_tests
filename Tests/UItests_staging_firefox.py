from os.path import dirname, join, abspath
import sys

sys.path.insert(0, abspath(join(dirname(__file__), '..')))
from Tests.UI_tests import *

# Variables for this test config
dotenv.load_dotenv(verbose=True)
wbdrv = 'firefox'
env = getenv('RI_STAGE')
path = '../test-reports/' + 'Test Run ' + time.strftime('%d %b %Y %H') + ' - Firefox - '

# Run the whole test suite
ui_tests(env, path, wbdrv)