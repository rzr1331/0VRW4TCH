"""
Scenario modules for testing.

Each module defines one threat scenario:
- cryptomining.py: Cryptomining detection test
- ransomware.py: Ransomware attack test
- data_exfiltration.py: Data exfiltration test
- credential_theft.py: Credential theft test
- container_escape.py: Container escape test
"""

# Import all scenarios to register them
# from .cryptomining import CryptominingScenario
from .ransomware import RansomwareScenario
# from .data_exfiltration import DataExfiltrationScenario
# from .credential_theft import CredentialTheftScenario
from .container_escape import ContainerEscapeScenario

__all__ = [
    # "CryptominingScenario",
    "RansomwareScenario", 
    # "DataExfiltrationScenario",
    # "CredentialTheftScenario",
    "ContainerEscapeScenario",
]
