from enum import Enum


class Roles(Enum):
    ADMIN = "Admin"
    DBD = "DBD"
    BDC = "BDC"
    CX = "CX"
    CUSTOMER_SERVICE = "CUSTOMER_SERVICE"
    SCM = "SCM"
    IM = "IM"
    PRICING = "PRICING"
    DC_STAFF = "DC_STAFF"
    CUSTOMER = "CUSTOMER"


roles_replacement_mapping = {
    "portal admins": "Admin",
    "dc": "Driver",
    "portal dc staff": "Driver",
    "portal dc managers": "Admin",
}
