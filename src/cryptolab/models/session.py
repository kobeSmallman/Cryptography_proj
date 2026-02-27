"""
SessionState = "memory"
This helps with the Continue/Restart for remembering values
Save into exports/session.json
Fields start as none and modules run these fields become populated
"""

from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional # type annotations

@dataclass
class SessionState:
   # RSA key generation
   rsa_p: Optional[int] = None
   rsa_q: Optional[int] = None
   rsa_n: Optional[int] = None
   rsa_phi_n: Optional[int] = None
   rsa_e: Optional[int] = None
   rsa_d: Optional[int] = None
   # Diffie-Hellman key exchange
   dh_p: Optional[int] = None
   dh_g: Optional[int] = None
   dh_a: Optional[int] = None
   dh_b: Optional[int] = None
   dh_A: Optional[int] = None
   dh_B: Optional[int] = None
   dh_s: Optional[int] = None
   #Diffie-Hellman key exchange + DES + signatures
   @staticmethod
   def new() -> "SessionState":
       return SessionState()
   def wipe(self) -> None:
       fresh = SessionState.new()
       self.__dict__.update(fresh.__dict__)
   def to_json_obj(self) -> Dict[str, Any]:
       return asdict(self)
   @staticmethod
   def from_json_obj(obj: Dict[str, Any]) -> "SessionState":
       return SessionState(**obj)
   def summary_for_menu(self) -> Dict[str, str]:
       """
       Status panel for main menu
       """
       # helper for yes/no
       def yn(v: object) -> str:
           return "YES" if v is not None else "NO"
       return {
           #"RSA values and DH and more values which what this does is to show if the values are present or not"
           "RSA keys present (p/q/n/phi_n/e/d)": f"{yn(self.rsa_p)}/{yn(self.rsa_q)}/{yn(self.rsa_n)}/{yn(self.rsa_phi_n)}/{yn(self.rsa_e)}/{yn(self.rsa_d)}",
           "DH values present (p/g/A/B/s)": f"{yn(self.dh_p)}/{yn(self.dh_g)}/{yn(self.dh_A)}/{yn(self.dh_B)}/{yn(self.dh_s)}"

       }