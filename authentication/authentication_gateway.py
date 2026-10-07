class AuthenticationGatewayService:
    # Coordinates Workspace lookup, authorization, and JWT creation
    # for an authenticated Greenhill employee.

    def __init__(
        self,
        directory_service,
        authorization_service,
        jwt_service,
    ):
        # Store the services so they can be injected and tested
        # independently without requiring live external systems.
        self.directory_service = directory_service
        self.authorization_service = authorization_service
        self.jwt_service = jwt_service

    def authenticate(self, email):
        # Retrieve the employee from Google Workspace Directory.
        employee = self.directory_service.get_user_by_email(
            email
        )

        # An employee who cannot be found in the Greenhill Workspace
        # Directory must not receive application access.
        if employee is None:
            raise ValueError(
                "Greenhill Workspace user was not found."
            )

        # Determine the employee's role and authorized systems.
        authorization = self.authorization_service.authorize(
            employee
        )

        # Create the application JWT containing the employee's
        # identity and authorization information.
        token = self.jwt_service.create_token(
            authorization
        )

        # Return the information required by the consuming
        # Greenhill applications.
        return {
            "email": authorization["email"],
            "role": authorization["role"],
            "authorized_systems": authorization[
                "authorized_systems"
            ],
            "token": token,
        }