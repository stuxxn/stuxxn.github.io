from uuid import UUID
import random
import jwt
from httpx import Client
from os import environ
from typing import Any

HTTP_HDR_AUTH: str = "Authorization"

HOST="https://192.168.60.10:4568"
API_ENDPOINT: str = "/api/identity/permissions/roleAssignments"
API_ROLE_ASSIGN_USER = "/api/administration/auth/account/{user_guid}/role-assignments"
SUPERVISOR_ROLE_GUID = UUID("5964077F-DEC3-4AA5-ADAF-B56B38A7007D")

g_client: Client = None


def randomize_case(value: str) -> str:
    return "".join(
        c.upper() if random.choice((True, False)) else c.lower()
        for c in value
    )

def query_role_assignments(user_guid: UUID) -> list[dict[str,Any]]:

    print(f"Query role assignments for user - {user_guid}")

    url = HOST + API_ROLE_ASSIGN_USER.format(user_guid = str(user_guid))
    print(f"URL: {url}")

    resp = g_client.get(url)
    resp.raise_for_status()

    return resp.json()["directAssignments"]


def patch_role_assignment(user_guid: UUID, role_guid: UUID) -> None:

    assigned_roles = query_role_assignments(user_guid)

    role_assignment = assigned_roles[0]
    print("Patching existing role assignment:", role_assignment)

    obj = {
            "id": str(role_assignment["roleAssignmentID"]),
            "userId": randomize_case(str(user_guid)),
            "roleId": randomize_case(str(role_guid)),
            "name":None,
            "assignmentType":4,
            "targetOuFilter":None,
            "targetGroup":None,
            "targetGroupName": None
    }

    url = HOST + API_ENDPOINT
    print(f"URL: {url}")
    print(f"Patch object:", obj)

    resp = g_client.patch(url, json=obj)
    resp.raise_for_status()


def main():

    print("Loading config from environment - JWT")
    JWT = environ["JWT"]

    global g_client
    g_client = Client(verify=False, headers= {
        HTTP_HDR_AUTH: f"Bearer {JWT}"
    })

    jwt_payload = jwt.decode(JWT, options={"verify_signature": False})
    user_guid = UUID(jwt_payload["userId"])

    print(f"Using User GUID from JWT - {user_guid}")
    print(f"Assign supervisor role - {str(SUPERVISOR_ROLE_GUID)}")

    patch_role_assignment(user_guid, SUPERVISOR_ROLE_GUID)


if __name__ == "__main__":
    main()
