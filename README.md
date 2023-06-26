# Simple Go HTTP Server

This is a simple HTTP server written in Go that demonstrates basic user registration, login, and authentication functionality using a PostgreSQL database.

## Prerequisites

To run the server, you need to have Go (version 1.16 or higher) installed on your system. Additionally, make sure you have a PostgreSQL database available and the required environment variables set.

## Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/ChARCOOL/golang-authentication
   ```

2. Change to the project directory:

   ```shell
   cd golang-authentication
   ```

3. Build the project:

   ```shell
   go build
   ```

## Configuration

The server uses the following environment variables for configuration:

- `POSTGRES_HOST`: The hostname of the PostgreSQL database server. Defaults to `localhost`.
- `POSTGRES_PORT`: The port number of the PostgreSQL database server. Defaults to `5432`.
- `POSTGRES_USER`: The username to authenticate with the PostgreSQL database server. Defaults to `postgres`.
- `POSTGRES_PASSWORD`: The password to authenticate with the PostgreSQL database server. Defaults to `postgres`.
- `POSTGRES_DB`: The name of the PostgreSQL database. Defaults to `postgres`.
- `LISTEN_ADDR`: The address on which the server will listen. Defaults to `:3000`.

Make sure to set these environment variables according to your PostgreSQL database configuration before starting the server.

## Usage

To start the server, run the following command:

```shell
./<executable-name>
```

The server will listen on the address specified by the `LISTEN_ADDR` environment variable (default: `:3000`).

## API Endpoints

The server provides the following API endpoints:

- `POST /user/register`: Registers a new user by providing a username, email, and password.
- `POST /user/login`: Logs in a user by providing their email and password.
- `GET /user/me`: Fetches the currently authenticated user's details.

## Database Connection

The server connects to a PostgreSQL database using the `github.com/lib/pq` driver. The connection details are retrieved from the environment variables `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB`. Make sure to set these environment variables with the appropriate values.