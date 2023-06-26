# Simple Go HTTP Server

This is a simple HTTP server written in Go that demonstrates basic user registration, login, and authentication functionality.

## Features

- User registration: Allows users to register by providing a username, email, and password.
- User login: Allows registered users to log in by providing their email and password.
- User authentication: Uses JSON Web Tokens (JWT) for authentication and generates an authentication token upon successful login.
- User retrieval: Provides an endpoint to fetch user details by decoding and verifying the authentication token.

## Prerequisites

To run the server, you need to have Go (version 1.16 or higher) installed on your system.

## Installation

1. Clone the repository:

```
git clone <repository-url>
```

2. Change to the project directory:

```
cd <project-directory>
```

3. Build the project:

```
go build
```

## Usage

To start the server, run the following command:

```
./<executable-name>
```

The server will listen on the default address `localhost:8000`.

## API Endpoints

The server provides the following API endpoints:

- `POST /user/register`: Registers a new user by providing a username, email, and password.
- `POST /user/login`: Logs in a user by providing their email and password.
- `GET /user/me`: Fetches the currently authenticated user's details.

## Configuration

The server uses the following environment variables for configuration:

- `JWT_SECRET_KEY`: The secret key used for signing and verifying JWTs. If not provided, a default value is used.

Make sure to set the environment variables accordingly before starting the server.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvement, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

Feel free to modify the README as per your requirements, adding additional information or sections if needed.