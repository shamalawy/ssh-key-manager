package dbtest

import "os"

func getenv(name string) string { return os.Getenv(name) }
