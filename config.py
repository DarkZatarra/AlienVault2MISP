import os

import dotenv


dotenv.load_dotenv()


OTX_KEY = os.getenv('OTX_KEY')
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_KEY')
