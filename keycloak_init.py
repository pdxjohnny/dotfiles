import getpass
import keyring
import argparse

from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection
from keycloak.exceptions import KeycloakGetError


def create_realm_and_assign_admin(args):
    keycloak_connection = KeycloakOpenIDConnection(
        server_url=args.server_url,
        username=args.admin_username,
        password=args.admin_password,
        realm_name="master",
        user_realm_name="only_if_other_realm_than_master",
        client_id="my_client",
        client_secret_key="client-secret",
        verify=True,
    )

    keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

    try:
        # Create the realm
        new_realm = keycloak_admin.create_realm(
            {"realm": args.realm_name, "enabled": True}
        )

        # Create a realm role
        new_realm_role = keycloak_admin.create_realm_role(
            args.realm_name, {"name": "admin", "description": "Realm Administrator"}
        )

        # Add the role to the user
        keycloak_admin.assign_realm_roles(args.realm_name, args.username, ["admin"])

        return True, "Realm and admin role created successfully."

    except KeycloakGetError as e:
        return False, str(e)


def parse_arguments():
    user = getpass.getuser()

    parser = argparse.ArgumentParser(
        description="Create a realm and admin user in Keycloak"
    )
    parser.add_argument(
        "--server-url",
        default=keyring.get_password(user, "admin.keycloak.server_url") or f"keycloak.{user}.localhost",
        help="URL of the Keycloak server: python -m keyring set $USER admin.keycloak.server_url. (default: %(default)s)",
    )
    parser.add_argument(
        "--admin-username",
        default=keyring.get_password(user, "admin.keycloak.username") or "admin",
        help="Admin username for Keycloak: echo admin | python -m keyring set $USER admin.keycloak.username. (default: %(default)s)",
    )
    parser.add_argument(
        "--admin-password",
        default=keyring.get_password(user, "admin.keycloak.password") or "admin",
        help="Admin password for Keycloak: head -n 99999 /dev/urandom | sha384sum - | awk '{print $1}' | tee /dev/stderr | python -m keyring set $USER admin.keycloak.password. (default: %(default)s)",
    )
    parser.add_argument(
        "--username",
        default=keyring.get_password(user, f"{user}.keycloak.username") or "alice",
        help="Username of the user to assign admin privileges: python -m keyring set $USER admin.keycloak.password. (default: %(default)s)",
    )
    parser.add_argument(
        "--password",
        default=keyring.get_password(user, f"{user}.keycloak.password") or "whoareyou?",
        help="Password of the user to assign admin privileges within new realm: head -n 99999 /dev/urandom | sha384sum - | awk '{print $1}' | tee /dev/stderr | python -m keyring set $USER $USER.keycloak.password. (default: %(default)s)",
    )
    parser.add_argument(
        "--realm-name",
        default=keyring.get_password(user, f"{user}.keycloak.realm") or "wonderland",
        help="Name of the realm to create within new realm: python -m keyring set $USER admin.keycloak.realm. (default: %(default)s)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    success, message = create_realm_and_assign_admin(args)
    if success:
        print(message)
    else:
        print("Error:", message)
