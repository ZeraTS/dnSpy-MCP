#!/usr/bin/env python3
import logging
import re
from typing import List, Tuple


def setup_logging(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def parse_range_expression(expr: str) -> List[int]:
    result = []
    parts = expr.split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part and part[0] != '-':
            start, end = part.split('-')
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(part))
    
    return result
