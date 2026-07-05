from pathlib import Path


_OUI_PATH = Path(__file__).parent / "oui.txt"




def load_oui_database(filepath) -> dict[str, str]:
    database = {}
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(base 16)" in line:
                before, after = line.split("(base 16)")
                oui = before.split()[0].upper()
                company = after.strip()
                database[oui] = company
    return database


OUI_DATABASE = load_oui_database(_OUI_PATH)


def lookup_manufacturer(mac_address: str, oui_database: dict[str, str]) -> str:
    oui = mac_address.replace(":", "")[:6].upper()
    return oui_database.get(oui, "Unknown")

