package main

func main() {
	host := GetEnv("POSTGRES_HOST", "localhost")
	port := GetEnv("POSTGRES_PORT", "5432")
	user := GetEnv("POSTGRES_USER", "postgres")
	password := GetEnv("POSTGRES_PASSWORD", "postgres")
	dbname := GetEnv("POSTGRES_DB", "postgres")

	ConnectDB(host, port, user, password, dbname)

	listenAddr := GetEnv("LISTEN_ADDR", ":3000")

	RunServer(listenAddr)
}
