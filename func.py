import json
from target import Target

import logging
logger = logging.getLogger(__name__)

TGS: list[Target] = []

def loadTGS():
    try:
        global TGS
        with open('sav.json', 'r', encoding='utf-8') as f:
            TGS = [Target.from_json(target) for target in json.loads(f.read())]
        logger.info(f'Loaded total {len(TGS)} targets')
    except FileNotFoundError:
        logger.fatal('No savfile found, must init first')
        exit(1)

def writeTGS():
    with open('sav.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps([target.to_json() for target in TGS]))
