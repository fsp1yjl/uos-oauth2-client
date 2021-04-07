package main

import (
	auth2engine "githut.com/fsp1yjl/auth2engine"
)

func main() {
	host := "localhost"
	port := "9094"

	eng := auth2engine.InitEngine()
	eng.Run(host + ":" + port )
}