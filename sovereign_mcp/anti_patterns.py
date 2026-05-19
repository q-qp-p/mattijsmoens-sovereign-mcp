"""
AntiPatternDetector — Universal AI Failure Mode Interceptor
===========================================================
Detects and blocks common LLM anti-patterns before they can execute.
"""

import re
import logging
from typing import Tuple, List, Dict, Any

logger = logging.getLogger(__name__)

class AntiPatternDetector:
    """
    Scans dictionaries (tool inputs/outputs) for AI anti-patterns.
    """

    @classmethod
    def scan_dict(cls, data: Dict[str, Any], action_type: str = "") -> Tuple[bool, List[Dict[str, str]]]:
        """
        Scan a dictionary for anti-patterns.
        
        Args:
            data: The tool parameters/output to scan
            action_type: The name of the tool/action (optional context)
            
        Returns:
            (is_clean: bool, detections: list of detection dicts)
        """
        detections = []
        is_clean = True

        for key, value in data.items():
            if not isinstance(value, str):
                continue
                
            value_lower = value.lower()
            
            # 1. Greedy Git
            if re.search(r"git\s+add\s+(\.|\*)", value):
                is_clean = False
                detections.append({
                    "category": "greedy_git",
                    "reason": "Explicitly list files to add instead of using '.' or '*'",
                    "match": value[:50]
                })

            # 2. Context Blindness
            if re.search(r"(cat|tail)\s+.*\.(log|sql|csv)(\s|$)", value) and not re.search(r"(head\s+-n|tail\s+-n|grep)", value):
                is_clean = False
                detections.append({
                    "category": "context_blindness",
                    "reason": "Do not read raw .log, .sql, or .csv files without bounds limits",
                    "match": value[:50]
                })
                
            # 3. Interactive Trap
            if re.match(r"^(npm|npx|apt-get|apt)\s", value) and not re.search(r"(-y|--yes|--non-interactive)", value):
                is_clean = False
                detections.append({
                    "category": "interactive_trap",
                    "reason": "Must pass -y or --yes flag for apt/npm/npx commands",
                    "match": value[:50]
                })

            # 4. CD Trap
            if re.search(r"(^|&&|;|\|)\s*cd\s+", value):
                is_clean = False
                detections.append({
                    "category": "cd_trap",
                    "reason": "Do not use 'cd' in commands; use the native 'cwd' argument instead",
                    "match": value[:50]
                })

            # 5. Binary Hallucination
            if re.search(r"[a-zA-Z0-9+/=]{500,}", value):
                is_clean = False
                detections.append({
                    "category": "binary_hallucination",
                    "reason": "Cannot write 500+ contiguous alphanumeric characters",
                    "match": "Binary data block"
                })

            # 6. Lazy Placeholder
            if re.search(r"(// rest of|<!-- existing|# rest of)", value_lower):
                is_clean = False
                detections.append({
                    "category": "lazy_placeholder",
                    "reason": "Do not use comments to skip code sections",
                    "match": "Placeholder detected"
                })

        return is_clean, detections
