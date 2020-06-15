import os

import dotenv


dotenv.load_dotenv()


OTX_KEY = os.getenv('OTX_KEY')
MISP_KEY = os.getenv('MISP_KEY')
